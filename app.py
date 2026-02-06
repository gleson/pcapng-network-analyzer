"""
PCAP Network Analyzer - Flask Web Application
Servidor web para análise de arquivos PCAP/PCAPNG
Com suporte a PostgreSQL, Celery e Redis
"""

import os
import json
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory, Response
from werkzeug.utils import secure_filename
import database as db

app = Flask(__name__)

# Configurações
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'data/uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB
app.config['ALLOWED_EXTENSIONS'] = {'pcap', 'pcapng'}

SETTINGS_FILE = os.environ.get('SETTINGS_FILE', 'data/settings.json')
RESULTS_FILE = 'data/results.json'

# Estado global da análise
analysis_status = {
    "status": "idle",  # idle, analyzing, completed, error
    "progress": 0,
    "message": "",
    "filename": "",
    "scan_id": None,
    "task_id": None
}

analysis_lock = threading.Lock()

# Check if Celery is available
CELERY_AVAILABLE = bool(os.environ.get('CELERY_BROKER_URL'))


def allowed_file(filename):
    """Verifica se o arquivo tem extensão permitida"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def load_settings():
    """Carrega configurações do arquivo JSON"""
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r') as f:
                return json.load(f)
        return {}
    except Exception as e:
        print(f"Error loading settings: {e}")
        return {}


def save_settings(settings):
    """Salva configurações no arquivo JSON"""
    try:
        os.makedirs(os.path.dirname(SETTINGS_FILE) or '.', exist_ok=True)
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving settings: {e}")
        return False


def load_results():
    """Carrega resultados da última análise"""
    try:
        if os.path.exists(RESULTS_FILE):
            with open(RESULTS_FILE, 'r') as f:
                return json.load(f)
        return None
    except Exception as e:
        print(f"Error loading results: {e}")
        return None


def save_results(results):
    """Salva resultados da análise"""
    try:
        with open(RESULTS_FILE, 'w') as f:
            json.dump(results, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving results: {e}")
        return False


def enrich_results_with_names_and_groups(results, settings):
    """Enrich results with IP names, groups, geolocation and reputation"""
    ip_names = db.get_all_ip_names()
    ip_geos = db.get_all_ip_geolocations()
    ip_reps = db.get_all_ip_reputations()
    trusted_ranges = settings.get('trusted_ranges', [])

    for ip_data in results.get('ips', []):
        ip_addr = ip_data.get('ip')

        # Add name
        ip_info = ip_names.get(ip_addr, {})
        ip_data['name'] = ip_info.get('name', '')

        # Add group (range description)
        group = db.get_ip_in_range(ip_addr, trusted_ranges)
        ip_data['group'] = group or ''

        # Add geolocation
        geo = ip_geos.get(ip_addr)
        if geo:
            ip_data['geolocation'] = geo

        # Add reputation
        rep = ip_reps.get(ip_addr)
        if rep:
            ip_data['reputation'] = rep

    # Also enrich protocol_ips if present
    protocol_ips = results.get('protocol_ips', {})
    for proto_name, ip_list in protocol_ips.items():
        for ip_data in ip_list:
            ip_addr = ip_data.get('ip')
            ip_info = ip_names.get(ip_addr, {})
            ip_data['name'] = ip_info.get('name', '')

    return results


def geolocate_ips(results):
    """Geolocate external IPs using ip-api.com (fallback when Celery not available)"""
    import time
    import requests as http_requests

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


def analyze_pcap_background(filepath, filename):
    """Fallback: análise em background usando threading (quando Celery não disponível)"""
    global analysis_status
    from pcap_analyzer import PCAPAnalyzer

    try:
        with analysis_lock:
            analysis_status["status"] = "analyzing"
            analysis_status["progress"] = 0
            analysis_status["message"] = "Loading packets..."
            analysis_status["filename"] = filename
            analysis_status["scan_id"] = None

        settings = load_settings()
        analyzer = PCAPAnalyzer(filepath, settings)

        with analysis_lock:
            analysis_status["progress"] = 20
            analysis_status["message"] = "Extracting IPs and protocols..."

        results = analyzer.analyze()

        with analysis_lock:
            analysis_status["progress"] = 60
            analysis_status["message"] = "Running security detections..."

        scan_id = db.save_scan(results, filename)

        with analysis_lock:
            analysis_status["progress"] = 75
            analysis_status["message"] = "Geolocating external IPs..."

        geolocate_ips(results)

        with analysis_lock:
            analysis_status["progress"] = 90
            analysis_status["message"] = "Checking threat intelligence..."

        try:
            from threat_intel import enrich_ips_with_reputation
            enrich_ips_with_reputation(results)
        except Exception as e:
            print(f"Threat intel error: {e}")

        results = enrich_results_with_names_and_groups(results, settings)
        save_results(results)

        with analysis_lock:
            analysis_status["status"] = "completed"
            analysis_status["progress"] = 100
            analysis_status["message"] = "Analysis completed successfully"
            analysis_status["scan_id"] = scan_id

    except Exception as e:
        print(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        with analysis_lock:
            analysis_status["status"] = "error"
            analysis_status["message"] = str(e)


# ===== ROTAS =====

@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html')


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload de arquivo PCAP/PCAPNG - inicia análise via Celery ou threading"""
    global analysis_status

    with analysis_lock:
        if analysis_status["status"] == "analyzing":
            return jsonify({
                "success": False,
                "error": "Analysis already in progress"
            }), 400

    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"success": False, "error": "Invalid file type. Only .pcap and .pcapng files are allowed"}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        settings = load_settings()

        if CELERY_AVAILABLE:
            from celery_app import analyze_pcap_task
            task = analyze_pcap_task.apply_async(args=[filepath, filename, settings])

            with analysis_lock:
                analysis_status["status"] = "analyzing"
                analysis_status["progress"] = 0
                analysis_status["message"] = "Starting analysis..."
                analysis_status["filename"] = filename
                analysis_status["task_id"] = task.id
                analysis_status["scan_id"] = None
        else:
            thread = threading.Thread(
                target=analyze_pcap_background,
                args=(filepath, filename)
            )
            thread.daemon = True
            thread.start()

        return jsonify({
            "success": True,
            "message": "File uploaded successfully. Analysis started.",
            "filename": filename
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/status', methods=['GET'])
def get_status():
    """Retorna status da análise em andamento"""
    global analysis_status

    with analysis_lock:
        task_id = analysis_status.get("task_id")

        if not task_id or not CELERY_AVAILABLE:
            return jsonify(analysis_status)

    # Check Celery task status
    from celery_app import analyze_pcap_task
    task = analyze_pcap_task.AsyncResult(task_id)

    with analysis_lock:
        if task.state == 'PROGRESS':
            meta = task.info or {}
            analysis_status.update({
                "status": "analyzing",
                "progress": meta.get('progress', 0),
                "message": meta.get('message', ''),
            })
        elif task.state == 'SUCCESS':
            result = task.result or {}
            analysis_status.update({
                "status": "completed",
                "progress": 100,
                "message": "Analysis completed successfully",
                "scan_id": result.get('scan_id'),
                "task_id": None
            })
        elif task.state == 'FAILURE':
            error_msg = str(task.info) if task.info else 'Unknown error'
            analysis_status.update({
                "status": "error",
                "message": error_msg,
                "task_id": None
            })

        return jsonify(analysis_status)


@app.route('/api/results', methods=['GET'])
def get_results():
    """Retorna resultados da análise"""
    scan_id = request.args.get('scan_id', type=int)
    view = request.args.get('view', 'single')
    scan_ids_param = request.args.get('scan_ids', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    settings = load_settings()

    try:
        if view == 'aggregate':
            scan_ids = None
            if scan_ids_param:
                scan_ids = [int(x) for x in scan_ids_param.split(',')]

            results = db.get_aggregated_results(
                scan_ids,
                settings.get('trusted_ranges', []),
                date_from=date_from or None,
                date_to=date_to or None
            )

            if not results['ips']:
                return jsonify({"success": False, "error": "No analysis results available"}), 404

            return jsonify({"success": True, "data": results, "view": "aggregate"})

        elif scan_id:
            results = db.get_scan_by_id(scan_id)
            if not results:
                return jsonify({"success": False, "error": "Scan not found"}), 404

            results = enrich_results_with_names_and_groups(results, settings)
            return jsonify({"success": True, "data": results, "scan_id": scan_id, "view": "single"})

        else:
            results = load_results()
            if results is None:
                return jsonify({"success": False, "error": "No analysis results available"}), 404

            results = enrich_results_with_names_and_groups(results, settings)
            return jsonify({"success": True, "data": results, "view": "single"})

    except Exception as e:
        print(f"Error getting results: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/scans', methods=['GET'])
def get_scans():
    """Retorna lista de todos os scans, com filtro opcional por período"""
    try:
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')

        scans = db.get_all_scans(
            date_from=date_from or None,
            date_to=date_to or None
        )
        return jsonify({"success": True, "data": scans})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/scans/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Remove um scan do histórico e o arquivo PCAP do disco"""
    try:
        filename = db.delete_scan(scan_id)
        if filename:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                os.remove(file_path)
            return jsonify({"success": True, "message": "Scan excluído com sucesso"})
        else:
            return jsonify({"success": False, "error": "Scan not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/scans/batch', methods=['DELETE'])
def delete_multiple_scans():
    """Remove múltiplos scans do histórico e os arquivos PCAP do disco"""
    try:
        data = request.get_json()
        scan_ids = data.get('ids', [])
        if not scan_ids:
            return jsonify({"success": False, "error": "Nenhum scan selecionado"}), 400

        filenames = db.delete_multiple_scans(scan_ids)
        for filename in filenames:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                os.remove(file_path)

        return jsonify({
            "success": True,
            "message": f"{len(filenames)} scan(s) excluído(s) com sucesso",
            "deleted_count": len(filenames)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Retorna configurações"""
    settings = load_settings()
    return jsonify({"success": True, "data": settings})


@app.route('/api/settings', methods=['POST'])
def update_settings():
    """Atualiza configurações"""
    try:
        new_settings = request.json
        if not new_settings:
            return jsonify({"success": False, "error": "No settings provided"}), 400

        if save_settings(new_settings):
            return jsonify({"success": True, "message": "Settings saved successfully"})
        else:
            return jsonify({"success": False, "error": "Failed to save settings"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ip-description', methods=['POST'])
def add_ip_description():
    """Adiciona/atualiza descrição de um IP (legacy)"""
    try:
        data = request.json
        ip = data.get('ip')
        description = data.get('description')

        if not ip or not description:
            return jsonify({"success": False, "error": "IP and description required"}), 400

        settings = load_settings()
        if 'ip_descriptions' not in settings:
            settings['ip_descriptions'] = {}
        settings['ip_descriptions'][ip] = description

        if save_settings(settings):
            return jsonify({"success": True, "message": "IP description saved"})
        else:
            return jsonify({"success": False, "error": "Failed to save"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ip-names', methods=['GET'])
def get_ip_names():
    """Retorna todos os nomes de IPs"""
    try:
        ip_names = db.get_all_ip_names()
        return jsonify({"success": True, "data": ip_names})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ip-names', methods=['POST'])
def set_ip_name():
    """Define o nome de um IP"""
    try:
        data = request.json
        ip = data.get('ip')
        name = data.get('name')
        description = data.get('description', '')

        if not ip or not name:
            return jsonify({"success": False, "error": "IP and name required"}), 400

        db.set_ip_name(ip, name, description)
        return jsonify({"success": True, "message": "IP name saved"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ip-names/<ip>', methods=['DELETE'])
def delete_ip_name(ip):
    """Remove o nome de um IP"""
    try:
        ip = ip.replace('-', '.')
        if db.delete_ip_name(ip):
            return jsonify({"success": True, "message": "IP name deleted"})
        else:
            return jsonify({"success": False, "error": "IP name not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ip-evolution/<ip>', methods=['GET'])
def get_ip_evolution(ip):
    """Retorna a evolução de um IP ao longo dos scans"""
    try:
        ip = ip.replace('-', '.')
        limit = request.args.get('limit', 10, type=int)
        evolution = db.get_ip_evolution(ip, limit)
        return jsonify({"success": True, "data": evolution})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/trusted-range', methods=['POST'])
def add_trusted_range():
    """Adiciona range de IP confiável"""
    try:
        data = request.json
        cidr = data.get('cidr')
        description = data.get('description', '')

        if not cidr:
            return jsonify({"success": False, "error": "CIDR required"}), 400

        settings = load_settings()
        if 'trusted_ranges' not in settings:
            settings['trusted_ranges'] = []

        for range_item in settings['trusted_ranges']:
            if range_item['cidr'] == cidr:
                return jsonify({"success": False, "error": "Range already exists"}), 400

        settings['trusted_ranges'].append({"cidr": cidr, "description": description})

        if save_settings(settings):
            return jsonify({"success": True, "message": "Trusted range added"})
        else:
            return jsonify({"success": False, "error": "Failed to save"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/trusted-range/<cidr>', methods=['DELETE'])
def delete_trusted_range(cidr):
    """Remove range de IP confiável"""
    try:
        settings = load_settings()
        if 'trusted_ranges' not in settings:
            return jsonify({"success": False, "error": "No trusted ranges found"}), 404

        cidr = cidr.replace('-', '/')
        original_len = len(settings['trusted_ranges'])
        settings['trusted_ranges'] = [r for r in settings['trusted_ranges'] if r['cidr'] != cidr]

        if len(settings['trusted_ranges']) == original_len:
            return jsonify({"success": False, "error": "Range not found"}), 404

        if save_settings(settings):
            return jsonify({"success": True, "message": "Trusted range removed"})
        else:
            return jsonify({"success": False, "error": "Failed to save"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/clear', methods=['POST'])
def clear_analysis():
    """Limpa análise atual"""
    global analysis_status

    try:
        with analysis_lock:
            if analysis_status["status"] == "analyzing":
                return jsonify({"success": False, "error": "Cannot clear while analysis is in progress"}), 400

            analysis_status = {
                "status": "idle", "progress": 0, "message": "",
                "filename": "", "scan_id": None, "task_id": None
            }

        if os.path.exists(RESULTS_FILE):
            os.remove(RESULTS_FILE)

        return jsonify({"success": True, "message": "Analysis cleared"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ===== PACKET VIEWER =====

@app.route('/api/packets/<int:scan_id>', methods=['GET'])
def get_packets(scan_id):
    """Get paginated packets from a scan's PCAP file"""
    try:
        scan = db.get_scan_by_id(scan_id)
        if not scan:
            return jsonify({"success": False, "error": "Scan not found"}), 404

        filename = scan['summary']['filename']
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        if not os.path.exists(filepath):
            return jsonify({"success": False, "error": "PCAP file not found on disk"}), 404

        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 200)
        filter_ip = request.args.get('filter_ip', '')
        filter_protocol = request.args.get('filter_protocol', '').upper()

        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Ether
        packets = rdpcap(filepath)

        filtered = []
        for i, pkt in enumerate(packets):
            if filter_ip:
                match = False
                if IP in pkt and (pkt[IP].src == filter_ip or pkt[IP].dst == filter_ip):
                    match = True
                elif IPv6 in pkt and (pkt[IPv6].src == filter_ip or pkt[IPv6].dst == filter_ip):
                    match = True
                if not match:
                    continue

            if filter_protocol:
                has_proto = False
                if filter_protocol == 'TCP' and TCP in pkt:
                    has_proto = True
                elif filter_protocol == 'UDP' and UDP in pkt:
                    has_proto = True
                elif filter_protocol == 'ICMP' and ICMP in pkt:
                    has_proto = True
                elif filter_protocol == 'ARP' and ARP in pkt:
                    has_proto = True
                elif filter_protocol == 'DNS' and DNS in pkt:
                    has_proto = True
                elif filter_protocol == 'HTTP' and TCP in pkt and (pkt[TCP].sport == 80 or pkt[TCP].dport == 80):
                    has_proto = True
                elif filter_protocol == 'HTTPS' and TCP in pkt and (pkt[TCP].sport == 443 or pkt[TCP].dport == 443):
                    has_proto = True
                if not has_proto:
                    continue

            filtered.append((i, pkt))

        total = len(filtered)
        start = (page - 1) * per_page
        page_packets = filtered[start:start + per_page]

        first_time = float(packets[0].time) if packets else 0

        packet_list = []
        for pkt_num, pkt in page_packets:
            info = {
                'number': pkt_num + 1,
                'time': round(float(pkt.time) - first_time, 6),
                'length': len(pkt),
                'protocol': 'Other',
                'src': '',
                'dst': '',
                'info': '',
            }

            if IP in pkt:
                info['src'] = pkt[IP].src
                info['dst'] = pkt[IP].dst
                if TCP in pkt:
                    sport, dport = pkt[TCP].sport, pkt[TCP].dport
                    flags = str(pkt[TCP].flags)
                    info['protocol'] = 'TCP'
                    info['info'] = f"{sport} \u2192 {dport} [{flags}] Len={len(pkt[TCP].payload)}"
                    if dport == 80 or sport == 80:
                        info['protocol'] = 'HTTP'
                    elif dport == 443 or sport == 443:
                        info['protocol'] = 'TLS'
                    elif dport == 22 or sport == 22:
                        info['protocol'] = 'SSH'
                    elif dport == 21 or sport == 21:
                        info['protocol'] = 'FTP'
                    elif dport == 23 or sport == 23:
                        info['protocol'] = 'Telnet'
                    elif dport == 53 or sport == 53:
                        info['protocol'] = 'DNS'
                elif UDP in pkt:
                    sport, dport = pkt[UDP].sport, pkt[UDP].dport
                    info['protocol'] = 'UDP'
                    info['info'] = f"{sport} \u2192 {dport} Len={len(pkt[UDP].payload)}"
                    if dport == 53 or sport == 53:
                        info['protocol'] = 'DNS'
                        if DNS in pkt and pkt[DNS].qr == 0:
                            try:
                                qname = pkt[DNS].qd.qname
                                if isinstance(qname, bytes):
                                    qname = qname.decode('utf-8', errors='ignore')
                                info['info'] = f"Query: {qname.rstrip('.')}"
                            except Exception:
                                pass
                elif ICMP in pkt:
                    info['protocol'] = 'ICMP'
                    info['info'] = f"Type={pkt[ICMP].type} Code={pkt[ICMP].code}"
            elif IPv6 in pkt:
                info['src'] = pkt[IPv6].src
                info['dst'] = pkt[IPv6].dst
                info['protocol'] = 'IPv6'
            elif ARP in pkt:
                info['protocol'] = 'ARP'
                info['src'] = pkt[ARP].psrc
                info['dst'] = pkt[ARP].pdst
                op = "Request" if pkt[ARP].op == 1 else "Reply"
                info['info'] = f"{op}: {pkt[ARP].psrc} is at {pkt[ARP].hwsrc}"

            packet_list.append(info)

        return jsonify({
            "success": True,
            "data": {
                "packets": packet_list,
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": max(1, (total + per_page - 1) // per_page)
            }
        })

    except Exception as e:
        print(f"Error reading packets: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/packets/<int:scan_id>/<int:packet_num>', methods=['GET'])
def get_packet_detail(scan_id, packet_num):
    """Get detailed information about a specific packet"""
    try:
        scan = db.get_scan_by_id(scan_id)
        if not scan:
            return jsonify({"success": False, "error": "Scan not found"}), 404

        filename = scan['summary']['filename']
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        if not os.path.exists(filepath):
            return jsonify({"success": False, "error": "PCAP file not found"}), 404

        from scapy.all import rdpcap
        packets = rdpcap(filepath)

        idx = packet_num - 1
        if idx < 0 or idx >= len(packets):
            return jsonify({"success": False, "error": "Invalid packet number"}), 404

        pkt = packets[idx]

        # Get layers
        layers = []
        layer = pkt
        while layer:
            layer_info = {
                'name': layer.__class__.__name__,
                'fields': {}
            }
            for field in layer.fields_desc:
                val = layer.getfieldval(field.name)
                if isinstance(val, bytes):
                    if len(val) <= 50:
                        val = val.hex()
                    else:
                        val = val[:50].hex() + f'... ({len(val)} bytes)'
                else:
                    val = str(val)
                layer_info['fields'][field.name] = val
            layers.append(layer_info)
            layer = layer.payload if layer.payload and not isinstance(layer.payload, bytes) else None

        # Hex dump
        raw_bytes = bytes(pkt)
        hex_lines = []
        for offset in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[offset:offset + 16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            hex_lines.append(f'{offset:04x}  {hex_part:<48}  {ascii_part}')

        return jsonify({
            "success": True,
            "data": {
                'number': packet_num,
                'summary': pkt.summary(),
                'layers': layers,
                'hexdump': '\n'.join(hex_lines),
                'length': len(pkt)
            }
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ===== REPORT GENERATION =====

@app.route('/api/report/<int:scan_id>', methods=['GET'])
def generate_report(scan_id):
    """Generate PDF or HTML report for a scan"""
    try:
        results = db.get_scan_by_id(scan_id)
        if not results:
            return jsonify({"success": False, "error": "Scan not found"}), 404

        settings = load_settings()
        results = enrich_results_with_names_and_groups(results, settings)

        report_format = request.args.get('format', 'pdf').lower()

        from report_generator import generate_pdf_report, generate_html_report

        if report_format == 'html':
            html_content = generate_html_report(results)
            filename = f"report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            return Response(
                html_content,
                mimetype='text/html',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
        else:
            output_path = f"/tmp/report_{scan_id}_{os.getpid()}.pdf"
            generate_pdf_report(results, output_path)

            with open(output_path, 'rb') as f:
                pdf_data = f.read()

            try:
                os.remove(output_path)
            except OSError:
                pass

            filename = f"report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            return Response(
                pdf_data,
                mimetype='application/pdf',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )

    except Exception as e:
        print(f"Error generating report: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


# Servir arquivos estáticos
@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('data', exist_ok=True)

    print("=" * 60)
    print("PCAP Network Analyzer v3.0 - Starting...")
    print("=" * 60)
    print("Server running at: http://localhost:5000")
    print(f"Database: {os.environ.get('DATABASE_URL', 'PostgreSQL')}")
    print(f"Celery: {'Enabled' if CELERY_AVAILABLE else 'Disabled (using threading)'}")
    print("=" * 60)

    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
