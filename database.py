"""
Database module for PCAP Network Analyzer
Manages PostgreSQL database for storing scan history, IP names and geolocation
"""

import psycopg2
import psycopg2.extras
import json
import os
from datetime import datetime
from contextlib import contextmanager
import ipaddress

DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://pcap_user:pcap_pass@localhost:5432/pcap_analyzer')


def init_database():
    """Initialize database and create tables if they don't exist"""
    with get_connection() as conn:
        cursor = conn.cursor()

        # Table for scans (captures)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                filename TEXT NOT NULL,
                analyzed_at TIMESTAMPTZ DEFAULT NOW(),
                packet_count INTEGER DEFAULT 0,
                total_bytes BIGINT DEFAULT 0,
                duration REAL DEFAULT 0,
                start_time TEXT,
                end_time TEXT,
                ip_count INTEGER DEFAULT 0,
                protocol_count INTEGER DEFAULT 0,
                alert_count INTEGER DEFAULT 0,
                results_json TEXT
            )
        ''')

        # Table for IP names (user-defined names for known hosts)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_names (
                id SERIAL PRIMARY KEY,
                ip_address TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        ''')

        # Table for IP statistics per scan
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_stats (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                is_local BOOLEAN DEFAULT FALSE,
                packets_sent INTEGER DEFAULT 0,
                packets_received INTEGER DEFAULT 0,
                bytes_sent BIGINT DEFAULT 0,
                bytes_received BIGINT DEFAULT 0,
                protocols TEXT,
                ports TEXT,
                alert_count INTEGER DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        ''')

        # Table for alerts per scan
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                ip_address TEXT,
                details TEXT,
                recommendation TEXT,
                timestamp TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        ''')

        # Table for protocol stats per scan
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protocol_stats (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                packets INTEGER DEFAULT 0,
                bytes BIGINT DEFAULT 0,
                percentage REAL DEFAULT 0,
                risk_level TEXT,
                warning TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        ''')

        # Table for protocol-IP statistics (IPs per protocol with stats)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protocol_ip_stats (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER NOT NULL,
                protocol_name TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                packets INTEGER DEFAULT 0,
                bytes BIGINT DEFAULT 0,
                is_local BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        ''')

        # Table for IP geolocation cache
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_geolocation (
                id SERIAL PRIMARY KEY,
                ip_address TEXT UNIQUE NOT NULL,
                country TEXT,
                country_code TEXT,
                city TEXT,
                region TEXT,
                lat REAL,
                lon REAL,
                isp TEXT,
                cached_at TIMESTAMPTZ DEFAULT NOW()
            )
        ''')

        # Table for IP reputation cache (threat intelligence)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_reputation (
                id SERIAL PRIMARY KEY,
                ip_address TEXT UNIQUE NOT NULL,
                reputation_score INTEGER DEFAULT 0,
                is_malicious BOOLEAN DEFAULT FALSE,
                abuse_confidence INTEGER DEFAULT 0,
                sources TEXT,
                last_seen TEXT,
                cached_at TIMESTAMPTZ DEFAULT NOW()
            )
        ''')

        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_stats_scan ON ip_stats(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_stats_ip ON ip_stats(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_scan ON alerts(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol_stats_scan ON protocol_stats(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol_ip_stats_scan ON protocol_ip_stats(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol_ip_stats_proto ON protocol_ip_stats(protocol_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_analyzed_at ON scans(analyzed_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_geolocation_ip ON ip_geolocation(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_reputation_ip ON ip_reputation(ip_address)')

        conn.commit()


@contextmanager
def get_connection():
    """Context manager for database connections"""
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ==================== SCAN OPERATIONS ====================

def save_scan(results, filename):
    """
    Save a complete scan to the database
    Returns the scan_id
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        summary = results.get('summary', {})
        ips = results.get('ips', [])
        protocols = results.get('protocols', [])
        alerts = results.get('alerts', [])

        # Insert scan
        cursor.execute('''
            INSERT INTO scans (
                filename, analyzed_at, packet_count, total_bytes, duration,
                start_time, end_time, ip_count, protocol_count, alert_count,
                results_json
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (
            filename,
            summary.get('analyzed_at', datetime.now().isoformat()),
            summary.get('packet_count', 0),
            summary.get('total_bytes', 0),
            summary.get('duration', 0),
            summary.get('start_time'),
            summary.get('end_time'),
            len(ips),
            len(protocols),
            len(alerts),
            json.dumps(results)
        ))

        scan_id = cursor.fetchone()['id']

        # Insert IP stats
        for ip_data in ips:
            cursor.execute('''
                INSERT INTO ip_stats (
                    scan_id, ip_address, is_local, packets_sent, packets_received,
                    bytes_sent, bytes_received, protocols, ports, alert_count
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                scan_id,
                ip_data.get('ip'),
                ip_data.get('is_local', False),
                ip_data.get('packets_sent', 0),
                ip_data.get('packets_received', 0),
                ip_data.get('bytes_sent', 0),
                ip_data.get('bytes_received', 0),
                json.dumps(ip_data.get('protocols', [])),
                json.dumps(ip_data.get('ports', [])),
                ip_data.get('alert_count', 0)
            ))

        # Insert alerts
        for alert in alerts:
            cursor.execute('''
                INSERT INTO alerts (
                    scan_id, severity, category, title, description,
                    ip_address, details, recommendation, timestamp
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                scan_id,
                alert.get('severity'),
                alert.get('category'),
                alert.get('title'),
                alert.get('description'),
                alert.get('ip'),
                json.dumps(alert.get('details', {})),
                alert.get('recommendation'),
                alert.get('timestamp')
            ))

        # Insert protocol stats
        for proto in protocols:
            cursor.execute('''
                INSERT INTO protocol_stats (
                    scan_id, name, packets, bytes, percentage, risk_level, warning
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                scan_id,
                proto.get('name'),
                proto.get('packets', 0),
                proto.get('bytes', 0),
                proto.get('percentage', 0),
                proto.get('risk_level'),
                proto.get('warning')
            ))

        # Insert protocol-IP stats
        protocol_ips = results.get('protocol_ips', {})
        for proto_name, ip_list in protocol_ips.items():
            for ip_data in ip_list:
                cursor.execute('''
                    INSERT INTO protocol_ip_stats (
                        scan_id, protocol_name, ip_address, packets, bytes, is_local
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                ''', (
                    scan_id,
                    proto_name,
                    ip_data.get('ip'),
                    ip_data.get('packets', 0),
                    ip_data.get('bytes', 0),
                    ip_data.get('is_local', False)
                ))

        conn.commit()
        return scan_id


def get_all_scans(date_from=None, date_to=None):
    """Get list of all scans (summary only), optionally filtered by date range"""
    with get_connection() as conn:
        cursor = conn.cursor()

        query = '''
            SELECT id, filename, analyzed_at, packet_count, total_bytes,
                   duration, ip_count, protocol_count, alert_count
            FROM scans
        '''
        params = []
        conditions = []

        if date_from:
            conditions.append('analyzed_at >= %s')
            params.append(date_from)
        if date_to:
            conditions.append('analyzed_at <= %s')
            params.append(date_to + ' 23:59:59')

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)

        query += ' ORDER BY analyzed_at DESC'

        cursor.execute(query, params)

        scans = []
        for row in cursor.fetchall():
            analyzed_at = row['analyzed_at']
            if hasattr(analyzed_at, 'isoformat'):
                analyzed_at = analyzed_at.isoformat()
            scans.append({
                'id': row['id'],
                'filename': row['filename'],
                'analyzed_at': analyzed_at,
                'packet_count': row['packet_count'],
                'total_bytes': row['total_bytes'],
                'duration': row['duration'],
                'ip_count': row['ip_count'],
                'protocol_count': row['protocol_count'],
                'alert_count': row['alert_count']
            })

        return scans


def get_scan_by_id(scan_id):
    """Get full scan results by ID"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT results_json FROM scans WHERE id = %s', (scan_id,))
        row = cursor.fetchone()

        if row:
            return json.loads(row['results_json'])
        return None


def delete_scan(scan_id):
    """Delete a scan and all related data. Returns the filename if deleted, None otherwise."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT filename FROM scans WHERE id = %s', (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        filename = row['filename']
        cursor.execute('DELETE FROM scans WHERE id = %s', (scan_id,))
        conn.commit()
        return filename


def delete_multiple_scans(scan_ids):
    """Delete multiple scans and all related data. Returns list of filenames deleted."""
    if not scan_ids:
        return []
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT filename FROM scans WHERE id = ANY(%s)', (scan_ids,))
        filenames = [row['filename'] for row in cursor.fetchall()]
        cursor.execute('DELETE FROM scans WHERE id = ANY(%s)', (scan_ids,))
        conn.commit()
        return filenames


# ==================== IP NAME OPERATIONS ====================

def get_ip_name(ip_address):
    """Get the name for a specific IP"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT name, description FROM ip_names WHERE ip_address = %s', (ip_address,))
        row = cursor.fetchone()

        if row:
            return {'name': row['name'], 'description': row['description']}
        return None


def get_all_ip_names():
    """Get all IP names"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT ip_address, name, description FROM ip_names ORDER BY ip_address')

        ip_names = {}
        for row in cursor.fetchall():
            ip_names[row['ip_address']] = {
                'name': row['name'],
                'description': row['description']
            }

        return ip_names


def set_ip_name(ip_address, name, description=None):
    """Set or update the name for an IP"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO ip_names (ip_address, name, description, updated_at)
            VALUES (%s, %s, %s, NOW())
            ON CONFLICT(ip_address) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                updated_at = NOW()
        ''', (ip_address, name, description))
        conn.commit()
        return True


def delete_ip_name(ip_address):
    """Delete the name for an IP"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM ip_names WHERE ip_address = %s', (ip_address,))
        deleted = cursor.rowcount > 0
        conn.commit()
        return deleted


# ==================== GEOLOCATION OPERATIONS ====================

def get_ip_geolocation(ip_address):
    """Get cached geolocation for an IP"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT country, country_code, city, region, lat, lon, isp, cached_at
            FROM ip_geolocation
            WHERE ip_address = %s
              AND cached_at > NOW() - INTERVAL '7 days'
        ''', (ip_address,))
        row = cursor.fetchone()
        if row:
            result = dict(row)
            if hasattr(result.get('cached_at'), 'isoformat'):
                result['cached_at'] = result['cached_at'].isoformat()
            return result
        return None


def get_all_ip_geolocations():
    """Get all cached geolocations"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ip_address, country, country_code, city, region, lat, lon, isp
            FROM ip_geolocation
            WHERE cached_at > NOW() - INTERVAL '7 days'
        ''')
        geos = {}
        for row in cursor.fetchall():
            geos[row['ip_address']] = {
                'country': row['country'],
                'country_code': row['country_code'],
                'city': row['city'],
                'region': row['region'],
                'lat': row['lat'],
                'lon': row['lon'],
                'isp': row['isp']
            }
        return geos


def save_ip_geolocation(ip_address, geo_data):
    """Save geolocation data for an IP"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO ip_geolocation (ip_address, country, country_code, city, region, lat, lon, isp, cached_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT(ip_address) DO UPDATE SET
                country = EXCLUDED.country,
                country_code = EXCLUDED.country_code,
                city = EXCLUDED.city,
                region = EXCLUDED.region,
                lat = EXCLUDED.lat,
                lon = EXCLUDED.lon,
                isp = EXCLUDED.isp,
                cached_at = NOW()
        ''', (
            ip_address,
            geo_data.get('country'),
            geo_data.get('countryCode'),
            geo_data.get('city'),
            geo_data.get('regionName'),
            geo_data.get('lat'),
            geo_data.get('lon'),
            geo_data.get('isp')
        ))
        conn.commit()


# ==================== AGGREGATE STATISTICS ====================

def get_ip_in_range(ip_str, trusted_ranges):
    """
    Check if an IP belongs to a trusted range and return the range description
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        for range_info in trusted_ranges:
            try:
                network = ipaddress.ip_network(range_info['cidr'], strict=False)
                if ip in network:
                    return range_info.get('description', range_info['cidr'])
            except ValueError:
                continue
    except ValueError:
        pass
    return None


def get_aggregated_results(scan_ids=None, trusted_ranges=None, date_from=None, date_to=None):
    """
    Get aggregated results from multiple scans
    If scan_ids is None, aggregates all scans (optionally filtered by date range)
    """
    trusted_ranges = trusted_ranges or []
    ip_names = get_all_ip_names()

    with get_connection() as conn:
        cursor = conn.cursor()

        # Build WHERE clause for scan filtering
        scan_conditions = []
        scan_params = []
        if scan_ids:
            scan_conditions.append('id = ANY(%s)')
            scan_params.append(scan_ids)
        if date_from:
            scan_conditions.append('analyzed_at >= %s')
            scan_params.append(date_from)
        if date_to:
            scan_conditions.append('analyzed_at <= %s')
            scan_params.append(date_to + ' 23:59:59')

        scan_where = ''
        if scan_conditions:
            scan_where = 'WHERE ' + ' AND '.join(scan_conditions)

        # Get matching scan IDs (for use in subqueries)
        cursor.execute(f'SELECT id FROM scans {scan_where}', scan_params)
        filtered_scan_ids = [row['id'] for row in cursor.fetchall()]

        if not filtered_scan_ids:
            return {
                'summary': {
                    'scan_count': 0,
                    'packet_count': 0,
                    'total_bytes': 0,
                    'duration': 0,
                    'first_scan': None,
                    'last_scan': None,
                    'analyzed_at': datetime.now().isoformat()
                },
                'ips': [],
                'protocols': [],
                'alerts': [],
                'protocol_ips': {},
                'traffic_timeline': []
            }

        # Use filtered IDs for all subsequent queries
        where_clause = 'WHERE scan_id = ANY(%s)'
        params = [filtered_scan_ids]

        # Get scan info
        cursor.execute(f'''
            SELECT COUNT(*) as scan_count,
                   SUM(packet_count) as total_packets,
                   SUM(total_bytes) as total_bytes,
                   SUM(duration) as total_duration,
                   MIN(start_time) as first_scan,
                   MAX(end_time) as last_scan
            FROM scans {scan_where}
        ''', scan_params)

        scan_summary = cursor.fetchone()

        # Aggregate IP stats
        cursor.execute(f'''
            SELECT
                ip_address,
                bool_or(is_local) as is_local,
                SUM(packets_sent) as packets_sent,
                SUM(packets_received) as packets_received,
                SUM(bytes_sent) as bytes_sent,
                SUM(bytes_received) as bytes_received,
                SUM(alert_count) as alert_count,
                COUNT(DISTINCT scan_id) as scan_count
            FROM ip_stats
            {where_clause}
            GROUP BY ip_address
            ORDER BY SUM(bytes_sent) + SUM(bytes_received) DESC
        ''', params)

        ips = []
        for row in cursor.fetchall():
            ip_addr = row['ip_address']

            # Get protocols from all scans for this IP
            cursor.execute('''
                SELECT protocols FROM ip_stats
                WHERE ip_address = %s AND scan_id = ANY(%s)
            ''', (ip_addr, filtered_scan_ids))

            protocols_set = set()
            for proto_row in cursor.fetchall():
                proto_list = json.loads(proto_row['protocols'] or '[]')
                protocols_set.update(proto_list)

            # Get name and group for this IP
            ip_info = ip_names.get(ip_addr, {})
            ip_name = ip_info.get('name', '')
            group = get_ip_in_range(ip_addr, trusted_ranges)

            ips.append({
                'ip': ip_addr,
                'name': ip_name,
                'group': group or '',
                'is_local': bool(row['is_local']),
                'packets_sent': row['packets_sent'],
                'packets_received': row['packets_received'],
                'bytes_sent': row['bytes_sent'],
                'bytes_received': row['bytes_received'],
                'protocols': list(protocols_set),
                'alert_count': row['alert_count'],
                'scan_count': row['scan_count']
            })

        # Aggregate protocol stats - first get total bytes
        cursor.execute(f'''
            SELECT SUM(bytes) as total_bytes
            FROM protocol_stats
            {where_clause}
        ''', params)
        total_bytes = cursor.fetchone()['total_bytes'] or 0

        cursor.execute(f'''
            SELECT
                name,
                SUM(packets) as packets,
                SUM(bytes) as bytes,
                MAX(risk_level) as risk_level,
                MAX(warning) as warning
            FROM protocol_stats
            {where_clause}
            GROUP BY name
            ORDER BY SUM(bytes) DESC
        ''', params)

        protocols = []
        for row in cursor.fetchall():
            percentage = (row['bytes'] / total_bytes * 100) if total_bytes > 0 else 0
            protocols.append({
                'name': row['name'],
                'packets': row['packets'],
                'bytes': row['bytes'],
                'percentage': round(percentage, 2),
                'risk_level': row['risk_level'],
                'warning': row['warning']
            })

        # Get all alerts
        cursor.execute(f'''
            SELECT
                a.severity, a.category, a.title, a.description,
                a.ip_address, a.details, a.recommendation, a.timestamp,
                s.filename
            FROM alerts a
            JOIN scans s ON a.scan_id = s.id
            WHERE a.scan_id = ANY(%s)
            ORDER BY
                CASE a.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                a.timestamp DESC
        ''', (filtered_scan_ids,))

        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'severity': row['severity'],
                'category': row['category'],
                'title': row['title'],
                'description': row['description'],
                'ip': row['ip_address'],
                'details': json.loads(row['details'] or '{}'),
                'recommendation': row['recommendation'],
                'timestamp': row['timestamp'],
                'filename': row['filename']
            })

        # Aggregate protocol-IP stats
        cursor.execute(f'''
            SELECT
                protocol_name,
                ip_address,
                SUM(packets) as packets,
                SUM(bytes) as bytes,
                bool_or(is_local) as is_local
            FROM protocol_ip_stats
            {where_clause}
            GROUP BY protocol_name, ip_address
            ORDER BY protocol_name, SUM(bytes) DESC
        ''', params)

        protocol_ips = {}
        for row in cursor.fetchall():
            proto_name = row['protocol_name']
            if proto_name not in protocol_ips:
                protocol_ips[proto_name] = []
            protocol_ips[proto_name].append({
                'ip': row['ip_address'],
                'packets': row['packets'],
                'bytes': row['bytes'],
                'is_local': bool(row['is_local'])
            })

        return {
            'summary': {
                'scan_count': scan_summary['scan_count'],
                'packet_count': scan_summary['total_packets'] or 0,
                'total_bytes': scan_summary['total_bytes'] or 0,
                'duration': scan_summary['total_duration'] or 0,
                'first_scan': scan_summary['first_scan'],
                'last_scan': scan_summary['last_scan'],
                'analyzed_at': datetime.now().isoformat()
            },
            'ips': ips,
            'protocols': protocols,
            'alerts': alerts,
            'protocol_ips': protocol_ips,
            'traffic_timeline': []
        }


def get_ip_evolution(ip_address, limit=10):
    """
    Get the evolution of an IP across multiple scans
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT
                s.id as scan_id,
                s.filename,
                s.analyzed_at,
                i.packets_sent,
                i.packets_received,
                i.bytes_sent,
                i.bytes_received,
                i.alert_count
            FROM ip_stats i
            JOIN scans s ON i.scan_id = s.id
            WHERE i.ip_address = %s
            ORDER BY s.analyzed_at DESC
            LIMIT %s
        ''', (ip_address, limit))

        evolution = []
        for row in cursor.fetchall():
            analyzed_at = row['analyzed_at']
            if hasattr(analyzed_at, 'isoformat'):
                analyzed_at = analyzed_at.isoformat()
            evolution.append({
                'scan_id': row['scan_id'],
                'filename': row['filename'],
                'analyzed_at': analyzed_at,
                'packets_sent': row['packets_sent'],
                'packets_received': row['packets_received'],
                'bytes_sent': row['bytes_sent'],
                'bytes_received': row['bytes_received'],
                'alert_count': row['alert_count']
            })

        return evolution


# ==================== THREAT INTELLIGENCE OPERATIONS ====================

def get_ip_reputation(ip_address):
    """Get cached reputation for an IP (7-day TTL)"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT reputation_score, is_malicious, abuse_confidence,
                   sources, last_seen, cached_at
            FROM ip_reputation
            WHERE ip_address = %s
              AND cached_at > NOW() - INTERVAL '7 days'
        ''', (ip_address,))
        row = cursor.fetchone()
        if row:
            result = dict(row)
            if hasattr(result.get('cached_at'), 'isoformat'):
                result['cached_at'] = result['cached_at'].isoformat()
            result['sources'] = json.loads(result.get('sources') or '[]')
            return result
        return None


def save_ip_reputation(ip_address, reputation_data):
    """Save reputation data for an IP"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO ip_reputation (
                ip_address, reputation_score, is_malicious,
                abuse_confidence, sources, last_seen, cached_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT(ip_address) DO UPDATE SET
                reputation_score = EXCLUDED.reputation_score,
                is_malicious = EXCLUDED.is_malicious,
                abuse_confidence = EXCLUDED.abuse_confidence,
                sources = EXCLUDED.sources,
                last_seen = EXCLUDED.last_seen,
                cached_at = NOW()
        ''', (
            ip_address,
            reputation_data.get('reputation_score', 0),
            reputation_data.get('is_malicious', False),
            reputation_data.get('abuse_confidence', 0),
            json.dumps(reputation_data.get('sources', [])),
            reputation_data.get('last_seen')
        ))
        conn.commit()


def get_all_ip_reputations():
    """Get all cached reputations (within 7-day TTL)"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ip_address, reputation_score, is_malicious,
                   abuse_confidence, sources, last_seen
            FROM ip_reputation
            WHERE cached_at > NOW() - INTERVAL '7 days'
        ''')
        reps = {}
        for row in cursor.fetchall():
            reps[row['ip_address']] = {
                'reputation_score': row['reputation_score'],
                'is_malicious': row['is_malicious'],
                'abuse_confidence': row['abuse_confidence'],
                'sources': json.loads(row['sources'] or '[]'),
                'last_seen': row['last_seen']
            }
        return reps


# Initialize database on import
init_database()
