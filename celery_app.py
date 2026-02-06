"""
Celery configuration and tasks for async PCAP analysis
"""
import os
import json
import time
import requests as http_requests
from celery import Celery
from pcap_analyzer import PCAPAnalyzer
import database as db

# Initialize Celery
celery = Celery(
    'pcap_analyzer',
    broker=os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    backend=os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
)

celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)


def _geolocate_ips(results):
    """Geolocate external IPs using ip-api.com (free, 45 req/min)"""
    external_ips = [
        ip_data['ip'] for ip_data in results.get('ips', [])
        if not ip_data.get('is_local', True)
    ]

    for ip_addr in external_ips:
        cached = db.get_ip_geolocation(ip_addr)
        if cached:
            continue

        try:
            resp = http_requests.get(
                f'http://ip-api.com/json/{ip_addr}',
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    db.save_ip_geolocation(ip_addr, data)
            time.sleep(1.5)
        except Exception as e:
            print(f"Geolocation error for {ip_addr}: {e}")


def _check_threat_intel(results):
    """Check threat intelligence for external IPs"""
    try:
        from threat_intel import enrich_ips_with_reputation
        enrich_ips_with_reputation(results)
    except Exception as e:
        print(f"Threat intel error: {e}")


@celery.task(bind=True, name='pcap_analyzer.analyze_pcap')
def analyze_pcap_task(self, filepath, filename, settings):
    """
    Celery task for PCAP analysis
    Updates progress via self.update_state()
    """
    try:
        self.update_state(
            state='PROGRESS',
            meta={'progress': 10, 'message': 'Loading packets...', 'filename': filename}
        )

        analyzer = PCAPAnalyzer(filepath, settings)

        self.update_state(
            state='PROGRESS',
            meta={'progress': 20, 'message': 'Extracting IPs and protocols...', 'filename': filename}
        )

        results = analyzer.analyze()

        self.update_state(
            state='PROGRESS',
            meta={'progress': 60, 'message': 'Running security detections...', 'filename': filename}
        )

        # Save to database
        scan_id = db.save_scan(results, filename)

        self.update_state(
            state='PROGRESS',
            meta={'progress': 75, 'message': 'Geolocating external IPs...', 'filename': filename}
        )

        _geolocate_ips(results)

        self.update_state(
            state='PROGRESS',
            meta={'progress': 90, 'message': 'Checking threat intelligence...', 'filename': filename}
        )

        _check_threat_intel(results)

        # Save results JSON for compatibility
        try:
            results_file = 'data/results.json'
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=4)
        except Exception:
            pass

        return {
            'status': 'completed',
            'scan_id': scan_id,
            'filename': filename
        }

    except Exception as e:
        self.update_state(
            state='FAILURE',
            meta={'error': str(e), 'filename': filename}
        )
        raise
