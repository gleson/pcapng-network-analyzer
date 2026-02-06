"""
Threat Intelligence Module
Integrates with AbuseIPDB and IPsum for IP reputation
"""
import os
import requests
import time
from datetime import datetime
import database as db

ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
IPSUM_URL = 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'

# In-memory cache for IPsum list (reload every 24h)
_ipsum_cache = {
    'ips': {},
    'last_updated': None
}


def load_ipsum_list():
    """Load IPsum reputation list from GitHub (malicious IPs with scores)"""
    global _ipsum_cache

    if _ipsum_cache['last_updated']:
        hours_old = (datetime.now() - _ipsum_cache['last_updated']).total_seconds() / 3600
        if hours_old < 24:
            return _ipsum_cache['ips']

    try:
        resp = requests.get(IPSUM_URL, timeout=15)
        if resp.status_code == 200:
            ips = {}
            for line in resp.text.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        ips[parts[0]] = int(parts[1])

            _ipsum_cache['ips'] = ips
            _ipsum_cache['last_updated'] = datetime.now()
            print(f"IPsum list loaded: {len(ips)} malicious IPs")
            return ips
    except Exception as e:
        print(f"Error loading IPsum list: {e}")

    return _ipsum_cache['ips']


def check_abuseipdb(ip_address):
    """Check IP reputation on AbuseIPDB (requires API key)"""
    if not ABUSEIPDB_API_KEY:
        return None

    try:
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90
        }
        resp = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params=params,
            timeout=5
        )

        if resp.status_code == 200:
            data = resp.json().get('data', {})
            return {
                'abuse_confidence': data.get('abuseConfidenceScore', 0),
                'is_malicious': data.get('abuseConfidenceScore', 0) > 50,
                'total_reports': data.get('totalReports', 0),
                'last_seen': data.get('lastReportedAt')
            }

        time.sleep(0.1)

    except Exception as e:
        print(f"AbuseIPDB error for {ip_address}: {e}")

    return None


def get_ip_reputation(ip_address):
    """
    Get combined reputation from multiple sources.
    Checks cache first, then IPsum and AbuseIPDB.
    """
    cached = db.get_ip_reputation(ip_address)
    if cached:
        return cached

    # Check IPsum (free, fast)
    ipsum_ips = load_ipsum_list()
    in_ipsum = ip_address in ipsum_ips
    ipsum_score = ipsum_ips.get(ip_address, 0)

    # Check AbuseIPDB (if API key available)
    abuse_data = check_abuseipdb(ip_address)

    # Combine results
    sources = []
    reputation_score = 0
    is_malicious = False
    abuse_confidence = 0
    last_seen = None

    if in_ipsum:
        sources.append('IPsum')
        reputation_score += min(ipsum_score * 25, 50)
        is_malicious = True

    if abuse_data:
        sources.append('AbuseIPDB')
        abuse_confidence = abuse_data['abuse_confidence']
        reputation_score += abuse_confidence
        is_malicious = is_malicious or abuse_data['is_malicious']
        last_seen = abuse_data.get('last_seen')

    reputation_score = min(reputation_score, 100)

    result = {
        'reputation_score': reputation_score,
        'is_malicious': is_malicious,
        'abuse_confidence': abuse_confidence,
        'sources': sources,
        'last_seen': last_seen
    }

    # Only cache if we actually checked something
    if sources or not ABUSEIPDB_API_KEY:
        db.save_ip_reputation(ip_address, result)

    return result


def enrich_ips_with_reputation(results):
    """Enrich external IPs with reputation data"""
    for ip_data in results.get('ips', []):
        if not ip_data.get('is_local', True):
            ip_addr = ip_data['ip']
            reputation = get_ip_reputation(ip_addr)
            ip_data['reputation'] = reputation

    return results
