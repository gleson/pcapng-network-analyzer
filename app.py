"""
PCAP Network Analyzer - Flask Web Application
Servidor web para análise de arquivos PCAP/PCAPNG
Com suporte a banco de dados para histórico de scans
"""

import os
import json
import threading
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from pcap_analyzer import PCAPAnalyzer
import database as db

app = Flask(__name__)

# Configurações
app.config['UPLOAD_FOLDER'] = 'data/uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB
app.config['ALLOWED_EXTENSIONS'] = {'pcap', 'pcapng'}

SETTINGS_FILE = 'data/settings.json'
RESULTS_FILE = 'data/results.json'

# Estado global da análise
analysis_status = {
    "status": "idle",  # idle, analyzing, completed, error
    "progress": 0,
    "message": "",
    "filename": "",
    "scan_id": None
}

analysis_lock = threading.Lock()


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
    """
    Enrich results with IP names and group (range description)
    """
    ip_names = db.get_all_ip_names()
    trusted_ranges = settings.get('trusted_ranges', [])

    for ip_data in results.get('ips', []):
        ip_addr = ip_data.get('ip')

        # Add name
        ip_info = ip_names.get(ip_addr, {})
        ip_data['name'] = ip_info.get('name', '')

        # Add group (range description)
        group = db.get_ip_in_range(ip_addr, trusted_ranges)
        ip_data['group'] = group or ''

    # Also enrich protocol_ips if present
    protocol_ips = results.get('protocol_ips', {})
    for proto_name, ip_list in protocol_ips.items():
        for ip_data in ip_list:
            ip_addr = ip_data.get('ip')
            ip_info = ip_names.get(ip_addr, {})
            ip_data['name'] = ip_info.get('name', '')

    return results


def analyze_pcap_background(filepath, filename):
    """
    Executa análise em background usando threading
    """
    global analysis_status

    try:
        with analysis_lock:
            analysis_status["status"] = "analyzing"
            analysis_status["progress"] = 0
            analysis_status["message"] = "Loading packets..."
            analysis_status["filename"] = filename
            analysis_status["scan_id"] = None

        # Carregar configurações
        settings = load_settings()

        # Criar analisador
        analyzer = PCAPAnalyzer(filepath, settings)

        # Atualizar progresso
        with analysis_lock:
            analysis_status["progress"] = 20
            analysis_status["message"] = "Extracting IPs and protocols..."

        # Executar análise
        results = analyzer.analyze()

        # Atualizar progresso
        with analysis_lock:
            analysis_status["progress"] = 80
            analysis_status["message"] = "Running security detections..."

        # Salvar no banco de dados
        scan_id = db.save_scan(results, filename)

        # Enriquecer com nomes e grupos
        results = enrich_results_with_names_and_groups(results, settings)

        # Salvar resultados em JSON também (para compatibilidade)
        save_results(results)

        # Análise completa
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
    """
    Upload de arquivo PCAP/PCAPNG
    Inicia análise em background
    """
    global analysis_status

    # Verificar se já há análise em andamento
    with analysis_lock:
        if analysis_status["status"] == "analyzing":
            return jsonify({
                "success": False,
                "error": "Analysis already in progress"
            }), 400

    # Verificar se arquivo foi enviado
    if 'file' not in request.files:
        return jsonify({
            "success": False,
            "error": "No file provided"
        }), 400

    file = request.files['file']

    # Verificar se arquivo foi selecionado
    if file.filename == '':
        return jsonify({
            "success": False,
            "error": "No file selected"
        }), 400

    # Verificar extensão
    if not allowed_file(file.filename):
        return jsonify({
            "success": False,
            "error": "Invalid file type. Only .pcap and .pcapng files are allowed"
        }), 400

    try:
        # Salvar arquivo
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Iniciar análise em background
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
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/status', methods=['GET'])
def get_status():
    """Retorna status da análise em andamento"""
    with analysis_lock:
        return jsonify(analysis_status)


@app.route('/api/results', methods=['GET'])
def get_results():
    """
    Retorna resultados da análise
    Query params:
    - scan_id: ID do scan específico (opcional)
    - view: 'single' ou 'aggregate' (default: single)
    - scan_ids: lista de IDs para agregação (comma-separated)
    """
    scan_id = request.args.get('scan_id', type=int)
    view = request.args.get('view', 'single')
    scan_ids_param = request.args.get('scan_ids', '')

    settings = load_settings()

    try:
        if view == 'aggregate':
            # Aggregate view
            scan_ids = None
            if scan_ids_param:
                scan_ids = [int(x) for x in scan_ids_param.split(',')]

            results = db.get_aggregated_results(scan_ids, settings.get('trusted_ranges', []))

            if not results['ips']:
                return jsonify({
                    "success": False,
                    "error": "No analysis results available"
                }), 404

            return jsonify({
                "success": True,
                "data": results,
                "view": "aggregate"
            })

        elif scan_id:
            # Specific scan
            results = db.get_scan_by_id(scan_id)

            if not results:
                return jsonify({
                    "success": False,
                    "error": "Scan not found"
                }), 404

            # Enrich with names and groups
            results = enrich_results_with_names_and_groups(results, settings)

            return jsonify({
                "success": True,
                "data": results,
                "scan_id": scan_id,
                "view": "single"
            })

        else:
            # Latest scan (from JSON file for compatibility)
            results = load_results()

            if results is None:
                return jsonify({
                    "success": False,
                    "error": "No analysis results available"
                }), 404

            # Enrich with names and groups
            results = enrich_results_with_names_and_groups(results, settings)

            return jsonify({
                "success": True,
                "data": results,
                "view": "single"
            })

    except Exception as e:
        print(f"Error getting results: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/scans', methods=['GET'])
def get_scans():
    """Retorna lista de todos os scans"""
    try:
        scans = db.get_all_scans()
        return jsonify({
            "success": True,
            "data": scans
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/scans/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Remove um scan do histórico"""
    try:
        if db.delete_scan(scan_id):
            return jsonify({
                "success": True,
                "message": "Scan deleted successfully"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Scan not found"
            }), 404
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Retorna configurações"""
    settings = load_settings()
    return jsonify({
        "success": True,
        "data": settings
    })


@app.route('/api/settings', methods=['POST'])
def update_settings():
    """Atualiza configurações"""
    try:
        new_settings = request.json

        if not new_settings:
            return jsonify({
                "success": False,
                "error": "No settings provided"
            }), 400

        if save_settings(new_settings):
            return jsonify({
                "success": True,
                "message": "Settings saved successfully"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Failed to save settings"
            }), 500

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/ip-description', methods=['POST'])
def add_ip_description():
    """Adiciona/atualiza descrição de um IP (legacy, for settings.json)"""
    try:
        data = request.json
        ip = data.get('ip')
        description = data.get('description')

        if not ip or not description:
            return jsonify({
                "success": False,
                "error": "IP and description required"
            }), 400

        settings = load_settings()

        if 'ip_descriptions' not in settings:
            settings['ip_descriptions'] = {}

        settings['ip_descriptions'][ip] = description

        if save_settings(settings):
            return jsonify({
                "success": True,
                "message": "IP description saved"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Failed to save"
            }), 500

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/ip-names', methods=['GET'])
def get_ip_names():
    """Retorna todos os nomes de IPs"""
    try:
        ip_names = db.get_all_ip_names()
        return jsonify({
            "success": True,
            "data": ip_names
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/ip-names', methods=['POST'])
def set_ip_name():
    """Define o nome de um IP"""
    try:
        data = request.json
        ip = data.get('ip')
        name = data.get('name')
        description = data.get('description', '')

        if not ip or not name:
            return jsonify({
                "success": False,
                "error": "IP and name required"
            }), 400

        db.set_ip_name(ip, name, description)

        return jsonify({
            "success": True,
            "message": "IP name saved"
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/ip-names/<ip>', methods=['DELETE'])
def delete_ip_name(ip):
    """Remove o nome de um IP"""
    try:
        # IP comes URL encoded, decode dots
        ip = ip.replace('-', '.')

        if db.delete_ip_name(ip):
            return jsonify({
                "success": True,
                "message": "IP name deleted"
            })
        else:
            return jsonify({
                "success": False,
                "error": "IP name not found"
            }), 404

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/ip-evolution/<ip>', methods=['GET'])
def get_ip_evolution(ip):
    """Retorna a evolução de um IP ao longo dos scans"""
    try:
        # IP comes URL encoded, decode dots
        ip = ip.replace('-', '.')
        limit = request.args.get('limit', 10, type=int)

        evolution = db.get_ip_evolution(ip, limit)

        return jsonify({
            "success": True,
            "data": evolution
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/trusted-range', methods=['POST'])
def add_trusted_range():
    """Adiciona range de IP confiável"""
    try:
        data = request.json
        cidr = data.get('cidr')
        description = data.get('description', '')

        if not cidr:
            return jsonify({
                "success": False,
                "error": "CIDR required"
            }), 400

        settings = load_settings()

        if 'trusted_ranges' not in settings:
            settings['trusted_ranges'] = []

        # Verificar se já existe
        for range_item in settings['trusted_ranges']:
            if range_item['cidr'] == cidr:
                return jsonify({
                    "success": False,
                    "error": "Range already exists"
                }), 400

        settings['trusted_ranges'].append({
            "cidr": cidr,
            "description": description
        })

        if save_settings(settings):
            return jsonify({
                "success": True,
                "message": "Trusted range added"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Failed to save"
            }), 500

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/trusted-range/<cidr>', methods=['DELETE'])
def delete_trusted_range(cidr):
    """Remove range de IP confiável"""
    try:
        settings = load_settings()

        if 'trusted_ranges' not in settings:
            return jsonify({
                "success": False,
                "error": "No trusted ranges found"
            }), 404

        # Decodificar CIDR (substitui / por -)
        cidr = cidr.replace('-', '/')

        # Remover range
        original_len = len(settings['trusted_ranges'])
        settings['trusted_ranges'] = [
            r for r in settings['trusted_ranges']
            if r['cidr'] != cidr
        ]

        if len(settings['trusted_ranges']) == original_len:
            return jsonify({
                "success": False,
                "error": "Range not found"
            }), 404

        if save_settings(settings):
            return jsonify({
                "success": True,
                "message": "Trusted range removed"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Failed to save"
            }), 500

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/clear', methods=['POST'])
def clear_analysis():
    """Limpa análise atual"""
    global analysis_status

    try:
        # Verificar se não está analisando
        with analysis_lock:
            if analysis_status["status"] == "analyzing":
                return jsonify({
                    "success": False,
                    "error": "Cannot clear while analysis is in progress"
                }), 400

            # Reset status
            analysis_status["status"] = "idle"
            analysis_status["progress"] = 0
            analysis_status["message"] = ""
            analysis_status["filename"] = ""
            analysis_status["scan_id"] = None

        # Remover arquivo de resultados
        if os.path.exists(RESULTS_FILE):
            os.remove(RESULTS_FILE)

        return jsonify({
            "success": True,
            "message": "Analysis cleared"
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# Servir arquivos estáticos
@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)


if __name__ == '__main__':
    # Criar diretórios se não existirem
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('data', exist_ok=True)

    # Iniciar servidor
    print("=" * 60)
    print("PCAP Network Analyzer - Starting...")
    print("=" * 60)
    print("Server running at: http://localhost:5000")
    print("Upload a .pcap or .pcapng file to begin analysis")
    print("Database: data/analyzer.db")
    print("=" * 60)

    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
