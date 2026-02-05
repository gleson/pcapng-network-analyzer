"""
Database module for PCAP Network Analyzer
Manages SQLite database for storing scan history and IP names
"""

import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager
import ipaddress

DATABASE_FILE = 'data/analyzer.db'


def init_database():
    """Initialize database and create tables if they don't exist"""
    os.makedirs('data', exist_ok=True)

    with get_connection() as conn:
        cursor = conn.cursor()

        # Table for scans (captures)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                packet_count INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Table for IP statistics per scan
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                is_local BOOLEAN DEFAULT 0,
                packets_sent INTEGER DEFAULT 0,
                packets_received INTEGER DEFAULT 0,
                bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0,
                protocols TEXT,
                ports TEXT,
                alert_count INTEGER DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        ''')

        # Table for alerts per scan
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                packets INTEGER DEFAULT 0,
                bytes INTEGER DEFAULT 0,
                percentage REAL DEFAULT 0,
                risk_level TEXT,
                warning TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        ''')

        # Table for protocol-IP statistics (IPs per protocol with stats)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protocol_ip_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                protocol_name TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                packets INTEGER DEFAULT 0,
                bytes INTEGER DEFAULT 0,
                is_local BOOLEAN DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        ''')

        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_stats_scan ON ip_stats(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_stats_ip ON ip_stats(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_scan ON alerts(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol_stats_scan ON protocol_stats(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol_ip_stats_scan ON protocol_ip_stats(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol_ip_stats_proto ON protocol_ip_stats(protocol_name)')

        conn.commit()


@contextmanager
def get_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
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
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

        scan_id = cursor.lastrowid

        # Insert IP stats
        for ip_data in ips:
            cursor.execute('''
                INSERT INTO ip_stats (
                    scan_id, ip_address, is_local, packets_sent, packets_received,
                    bytes_sent, bytes_received, protocols, ports, alert_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
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
                    ) VALUES (?, ?, ?, ?, ?, ?)
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


def get_all_scans():
    """Get list of all scans (summary only)"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, filename, analyzed_at, packet_count, total_bytes,
                   duration, ip_count, protocol_count, alert_count
            FROM scans
            ORDER BY analyzed_at DESC
        ''')

        scans = []
        for row in cursor.fetchall():
            scans.append({
                'id': row['id'],
                'filename': row['filename'],
                'analyzed_at': row['analyzed_at'],
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
        cursor.execute('SELECT results_json FROM scans WHERE id = ?', (scan_id,))
        row = cursor.fetchone()

        if row:
            return json.loads(row['results_json'])
        return None


def delete_scan(scan_id):
    """Delete a scan and all related data"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        conn.commit()
        return cursor.rowcount > 0


# ==================== IP NAME OPERATIONS ====================

def get_ip_name(ip_address):
    """Get the name for a specific IP"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT name, description FROM ip_names WHERE ip_address = ?', (ip_address,))
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
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(ip_address) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                updated_at = CURRENT_TIMESTAMP
        ''', (ip_address, name, description))
        conn.commit()
        return True


def delete_ip_name(ip_address):
    """Delete the name for an IP"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM ip_names WHERE ip_address = ?', (ip_address,))
        conn.commit()
        return cursor.rowcount > 0


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


def get_aggregated_results(scan_ids=None, trusted_ranges=None):
    """
    Get aggregated results from multiple scans
    If scan_ids is None, aggregates all scans
    """
    trusted_ranges = trusted_ranges or []
    ip_names = get_all_ip_names()

    with get_connection() as conn:
        cursor = conn.cursor()

        # Build WHERE clause
        where_clause = ''
        params = []
        if scan_ids:
            placeholders = ','.join('?' * len(scan_ids))
            where_clause = f'WHERE scan_id IN ({placeholders})'
            params = scan_ids

        # Get scan info
        if scan_ids:
            scan_where = f'WHERE id IN ({",".join("?" * len(scan_ids))})'
            cursor.execute(f'''
                SELECT COUNT(*) as scan_count,
                       SUM(packet_count) as total_packets,
                       SUM(total_bytes) as total_bytes,
                       SUM(duration) as total_duration,
                       MIN(start_time) as first_scan,
                       MAX(end_time) as last_scan
                FROM scans {scan_where}
            ''', scan_ids)
        else:
            cursor.execute('''
                SELECT COUNT(*) as scan_count,
                       SUM(packet_count) as total_packets,
                       SUM(total_bytes) as total_bytes,
                       SUM(duration) as total_duration,
                       MIN(start_time) as first_scan,
                       MAX(end_time) as last_scan
                FROM scans
            ''')

        scan_summary = cursor.fetchone()

        # Aggregate IP stats
        cursor.execute(f'''
            SELECT
                ip_address,
                MAX(is_local) as is_local,
                SUM(packets_sent) as packets_sent,
                SUM(packets_received) as packets_received,
                SUM(bytes_sent) as bytes_sent,
                SUM(bytes_received) as bytes_received,
                SUM(alert_count) as alert_count,
                COUNT(DISTINCT scan_id) as scan_count
            FROM ip_stats
            {where_clause}
            GROUP BY ip_address
            ORDER BY bytes_sent + bytes_received DESC
        ''', params)

        ips = []
        all_protocols = set()

        for row in cursor.fetchall():
            ip_addr = row['ip_address']

            # Get protocols from all scans for this IP
            if scan_ids:
                cursor.execute(f'''
                    SELECT protocols FROM ip_stats
                    WHERE ip_address = ? AND scan_id IN ({",".join("?" * len(scan_ids))})
                ''', [ip_addr] + scan_ids)
            else:
                cursor.execute('SELECT protocols FROM ip_stats WHERE ip_address = ?', (ip_addr,))

            protocols = set()
            for proto_row in cursor.fetchall():
                proto_list = json.loads(proto_row['protocols'] or '[]')
                protocols.update(proto_list)

            all_protocols.update(protocols)

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
                'protocols': list(protocols),
                'alert_count': row['alert_count'],
                'scan_count': row['scan_count']
            })

        # Aggregate protocol stats
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
            ORDER BY bytes DESC
        ''', params)

        protocols = []
        total_bytes = sum(row['bytes'] or 0 for row in cursor.fetchall())
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
            ORDER BY bytes DESC
        ''', params)

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
            {where_clause.replace('scan_id', 'a.scan_id') if where_clause else ''}
            ORDER BY
                CASE a.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                a.timestamp DESC
        ''', params)

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
                MAX(is_local) as is_local
            FROM protocol_ip_stats
            {where_clause.replace('scan_id', 'scan_id') if where_clause else ''}
            GROUP BY protocol_name, ip_address
            ORDER BY protocol_name, bytes DESC
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
            'traffic_timeline': []  # Not aggregated for simplicity
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
            WHERE i.ip_address = ?
            ORDER BY s.analyzed_at DESC
            LIMIT ?
        ''', (ip_address, limit))

        evolution = []
        for row in cursor.fetchall():
            evolution.append({
                'scan_id': row['scan_id'],
                'filename': row['filename'],
                'analyzed_at': row['analyzed_at'],
                'packets_sent': row['packets_sent'],
                'packets_received': row['packets_received'],
                'bytes_sent': row['bytes_sent'],
                'bytes_received': row['bytes_received'],
                'alert_count': row['alert_count']
            })

        return evolution


# Initialize database on import
init_database()
