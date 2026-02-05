"""
PCAP Network Analyzer
Motor de análise de arquivos .pcap/.pcapng com detecção de ameaças de segurança
"""

import math
import ipaddress
from collections import defaultdict, Counter
from datetime import datetime
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ARP, DNS, DNSQR, ICMP, Raw, Ether
from scapy.layers.http import HTTP, HTTPRequest


class PCAPAnalyzer:
    """
    Analisador de arquivos PCAP/PCAPNG
    Extrai informações de rede e detecta ameaças de segurança
    """

    # Portas suspeitas conhecidas
    SUSPICIOUS_PORTS = {
        4444: ("Metasploit Default", "critical"),
        666: ("Doom Backdoor", "critical"),
        1337: ("Leet/Hacker Culture", "high"),
        6666: ("IRC Backdoor", "critical"),
        6667: ("IRC (pode ser C2)", "medium"),
        27374: ("SubSeven Trojan", "critical"),
        31337: ("Back Orifice", "critical"),
        65000: ("Várias Backdoors", "critical"),
        5555: ("Android ADB", "high"),
        9001: ("Tor Default", "medium"),
        1080: ("SOCKS Proxy", "medium"),
    }

    # Portas SMB
    SMB_PORTS = {445, 139}

    # Classificação de risco por protocolo
    PROTOCOL_RISK = {
        # Baixo risco
        'DNS': ('low', None),
        'HTTPS': ('low', None),
        'TLS': ('low', None),
        'SSH': ('low', None),
        'ICMP': ('low', None),
        'NTP': ('low', None),
        'DHCP': ('low', None),

        # Médio risco
        'TCP': ('medium', None),
        'UDP': ('medium', None),
        'HTTP': ('medium', 'Unencrypted traffic - data can be intercepted'),
        'SMTP': ('medium', 'Verify TLS/STARTTLS usage'),
        'IPv6': ('medium', None),

        # Alto risco
        'FTP': ('high', 'Insecure protocol - credentials in plain text'),
        'Telnet': ('high', 'Extremely insecure protocol - avoid use'),
        'ARP': ('high', 'Monitor for spoofing attacks'),
        'SMB': ('high', 'Verify proper authentication and encryption'),
        'SMBv1': ('high', 'Obsolete version with known vulnerabilities'),
        'SNMP': ('high', 'Verify if using v3 with authentication'),
    }

    def __init__(self, filepath, settings=None):
        """
        Inicializa o analisador

        Args:
            filepath: Caminho para o arquivo .pcap/.pcapng
            settings: Dicionário com configurações (thresholds, etc.)
        """
        self.filepath = filepath
        self.settings = settings or {}
        self.packets = None
        self.results = {
            "summary": {},
            "ips": [],
            "protocols": [],
            "alerts": [],
            "traffic_timeline": [],
            "mac_ip_mapping": {},  # Mapeamento MAC -> IPs
            "ip_mac_mapping": {},  # Mapeamento IP -> MACs
            "protocol_ips": {}     # Protocolo -> lista de IPs
        }

    def analyze(self):
        """
        Executa a análise completa do arquivo PCAP

        Returns:
            dict: Resultados da análise
        """
        try:
            # Carregar pacotes
            print(f"Loading packets from {self.filepath}...")
            self.packets = rdpcap(self.filepath)
            print(f"Loaded {len(self.packets)} packets")

            # Extrair informações básicas
            self._extract_summary()

            # Extrair mapeamento MAC-IP
            self._extract_mac_ip_mapping()

            # Extrair IPs e estatísticas
            self._extract_ips()

            # Extrair protocolos (com IPs por protocolo)
            self._extract_protocols()

            # Executar detecções de segurança
            self._run_detections()

            # Classificar risco de protocolos
            self._classify_protocol_risks()

            # Gerar timeline de tráfego
            self._generate_traffic_timeline()

            # Contar alertas por IP
            self._count_alerts_per_ip()

            return self.results

        except Exception as e:
            print(f"Error analyzing PCAP: {e}")
            raise

    def _extract_summary(self):
        """Extrai informações resumidas do arquivo"""
        if not self.packets:
            return

        first_packet = self.packets[0]
        last_packet = self.packets[-1]

        total_bytes = sum(len(pkt) for pkt in self.packets)

        self.results["summary"] = {
            "filename": self.filepath.split('/')[-1],
            "analyzed_at": datetime.now().isoformat(),
            "packet_count": len(self.packets),
            "duration": float(last_packet.time - first_packet.time),
            "start_time": datetime.fromtimestamp(float(first_packet.time)).isoformat(),
            "end_time": datetime.fromtimestamp(float(last_packet.time)).isoformat(),
            "total_bytes": total_bytes
        }

    def _extract_mac_ip_mapping(self):
        """Extrai mapeamento entre endereços MAC e IP"""
        mac_to_ips = defaultdict(set)
        ip_to_macs = defaultdict(set)

        for pkt in self.packets:
            # Extrair MAC de camada Ethernet
            if Ether in pkt:
                src_mac = pkt[Ether].src
                dst_mac = pkt[Ether].dst

                # Mapear com IPv4
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst

                    if src_mac and src_ip:
                        mac_to_ips[src_mac].add(src_ip)
                        ip_to_macs[src_ip].add(src_mac)

                    if dst_mac and dst_ip:
                        mac_to_ips[dst_mac].add(dst_ip)
                        ip_to_macs[dst_ip].add(dst_mac)

                # Mapear com IPv6
                if IPv6 in pkt:
                    src_ip = pkt[IPv6].src
                    dst_ip = pkt[IPv6].dst

                    if src_mac and src_ip:
                        mac_to_ips[src_mac].add(src_ip)
                        ip_to_macs[src_ip].add(src_mac)

                    if dst_mac and dst_ip:
                        mac_to_ips[dst_mac].add(dst_ip)
                        ip_to_macs[dst_ip].add(dst_mac)

            # ARP também fornece mapeamento
            if ARP in pkt:
                arp_mac = pkt[ARP].hwsrc
                arp_ip = pkt[ARP].psrc
                if arp_mac and arp_ip:
                    mac_to_ips[arp_mac].add(arp_ip)
                    ip_to_macs[arp_ip].add(arp_mac)

        # Converter sets para listas para serialização JSON
        self.results["mac_ip_mapping"] = {mac: list(ips) for mac, ips in mac_to_ips.items()}
        self.results["ip_mac_mapping"] = {ip: list(macs) for ip, macs in ip_to_macs.items()}

    def _extract_ips(self):
        """Extrai todos os IPs e suas estatísticas"""
        ip_stats = defaultdict(lambda: {
            "packets_sent": 0,
            "packets_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "protocols": set(),
            "ports": set(),
            "is_local": False,
            "alert_count": 0,
            "macs": set()
        })

        for pkt in self.packets:
            # IPv4
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                pkt_size = len(pkt)

                # Estatísticas de origem
                ip_stats[src_ip]["packets_sent"] += 1
                ip_stats[src_ip]["bytes_sent"] += pkt_size
                ip_stats[src_ip]["is_local"] = self._is_local_ip(src_ip)

                # Estatísticas de destino
                ip_stats[dst_ip]["packets_received"] += 1
                ip_stats[dst_ip]["bytes_received"] += pkt_size
                ip_stats[dst_ip]["is_local"] = self._is_local_ip(dst_ip)

                # Protocolos
                if TCP in pkt:
                    ip_stats[src_ip]["protocols"].add("TCP")
                    ip_stats[src_ip]["ports"].add(pkt[TCP].dport)
                elif UDP in pkt:
                    ip_stats[src_ip]["protocols"].add("UDP")
                    ip_stats[src_ip]["ports"].add(pkt[UDP].dport)
                elif ICMP in pkt:
                    ip_stats[src_ip]["protocols"].add("ICMP")

                # MACs associados
                if Ether in pkt:
                    ip_stats[src_ip]["macs"].add(pkt[Ether].src)
                    ip_stats[dst_ip]["macs"].add(pkt[Ether].dst)

            # IPv6
            if IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                pkt_size = len(pkt)

                ip_stats[src_ip]["packets_sent"] += 1
                ip_stats[src_ip]["bytes_sent"] += pkt_size
                ip_stats[src_ip]["is_local"] = self._is_local_ip(src_ip)
                ip_stats[src_ip]["protocols"].add("IPv6")

                ip_stats[dst_ip]["packets_received"] += 1
                ip_stats[dst_ip]["bytes_received"] += pkt_size
                ip_stats[dst_ip]["is_local"] = self._is_local_ip(dst_ip)

                if Ether in pkt:
                    ip_stats[src_ip]["macs"].add(pkt[Ether].src)
                    ip_stats[dst_ip]["macs"].add(pkt[Ether].dst)

        # Converter para lista
        self.results["ips"] = [
            {
                "ip": ip,
                "is_local": data["is_local"],
                "packets_sent": data["packets_sent"],
                "packets_received": data["packets_received"],
                "bytes_sent": data["bytes_sent"],
                "bytes_received": data["bytes_received"],
                "protocols": list(data["protocols"]),
                "ports": sorted(list(data["ports"]))[:50],  # Limitar a 50 portas
                "alert_count": 0,  # Será atualizado depois
                "macs": list(data["macs"])  # MACs associados
            }
            for ip, data in ip_stats.items()
        ]

        # Ordenar por tráfego total
        self.results["ips"].sort(
            key=lambda x: x["bytes_sent"] + x["bytes_received"],
            reverse=True
        )

    def _extract_protocols(self):
        """Extrai estatísticas de protocolos e IPs por protocolo com estatísticas detalhadas"""
        protocol_stats = defaultdict(lambda: {"packets": 0, "bytes": 0, "ips": set()})
        # Estatísticas de IP por protocolo: protocol -> ip -> {packets, bytes}
        protocol_ip_stats = defaultdict(lambda: defaultdict(lambda: {"packets": 0, "bytes": 0}))
        total_bytes = 0

        def add_protocol_stats(proto_name, pkt_size, src_ip, dst_ip):
            """Helper para adicionar estatísticas de protocolo"""
            protocol_stats[proto_name]["packets"] += 1
            protocol_stats[proto_name]["bytes"] += pkt_size
            if src_ip:
                protocol_stats[proto_name]["ips"].add(src_ip)
                protocol_ip_stats[proto_name][src_ip]["packets"] += 1
                protocol_ip_stats[proto_name][src_ip]["bytes"] += pkt_size
            if dst_ip:
                protocol_stats[proto_name]["ips"].add(dst_ip)
                protocol_ip_stats[proto_name][dst_ip]["packets"] += 1
                protocol_ip_stats[proto_name][dst_ip]["bytes"] += pkt_size

        for pkt in self.packets:
            pkt_size = len(pkt)
            total_bytes += pkt_size

            src_ip = None
            dst_ip = None

            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst

            # Identificar protocolos
            if TCP in pkt:
                add_protocol_stats("TCP", pkt_size, src_ip, dst_ip)

                # Protocolos específicos sobre TCP
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport

                if dport == 80 or sport == 80:
                    add_protocol_stats("HTTP", pkt_size, src_ip, dst_ip)

                elif dport == 443 or sport == 443:
                    add_protocol_stats("HTTPS", pkt_size, src_ip, dst_ip)

                elif dport == 22 or sport == 22:
                    add_protocol_stats("SSH", pkt_size, src_ip, dst_ip)

                elif dport == 21 or sport == 21:
                    add_protocol_stats("FTP", pkt_size, src_ip, dst_ip)

                elif dport == 23 or sport == 23:
                    add_protocol_stats("Telnet", pkt_size, src_ip, dst_ip)

                elif dport == 25 or sport == 25:
                    add_protocol_stats("SMTP", pkt_size, src_ip, dst_ip)

                elif dport in self.SMB_PORTS or sport in self.SMB_PORTS:
                    add_protocol_stats("SMB", pkt_size, src_ip, dst_ip)

            elif UDP in pkt:
                add_protocol_stats("UDP", pkt_size, src_ip, dst_ip)

                # DNS
                if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                    add_protocol_stats("DNS", pkt_size, src_ip, dst_ip)

            elif ICMP in pkt:
                add_protocol_stats("ICMP", pkt_size, src_ip, dst_ip)

            elif ARP in pkt:
                protocol_stats["ARP"]["packets"] += 1
                protocol_stats["ARP"]["bytes"] += pkt_size
                # ARP não tem IP da mesma forma, usar psrc/pdst
                arp_src = pkt[ARP].psrc
                arp_dst = pkt[ARP].pdst
                if arp_src:
                    protocol_stats["ARP"]["ips"].add(arp_src)
                    protocol_ip_stats["ARP"][arp_src]["packets"] += 1
                    protocol_ip_stats["ARP"][arp_src]["bytes"] += pkt_size
                if arp_dst:
                    protocol_stats["ARP"]["ips"].add(arp_dst)
                    protocol_ip_stats["ARP"][arp_dst]["packets"] += 1
                    protocol_ip_stats["ARP"][arp_dst]["bytes"] += pkt_size

        # Armazenar IPs por protocolo com estatísticas detalhadas
        self.results["protocol_ips"] = {}
        for proto, ip_data in protocol_ip_stats.items():
            self.results["protocol_ips"][proto] = [
                {
                    "ip": ip,
                    "packets": stats["packets"],
                    "bytes": stats["bytes"],
                    "is_local": self._is_local_ip(ip)
                }
                for ip, stats in sorted(ip_data.items(), key=lambda x: x[1]["bytes"], reverse=True)
            ]

        # Converter para lista e calcular percentuais
        self.results["protocols"] = [
            {
                "name": proto,
                "packets": data["packets"],
                "bytes": data["bytes"],
                "percentage": round((data["bytes"] / total_bytes * 100), 2) if total_bytes > 0 else 0,
                "risk_level": "medium",  # Será atualizado
                "warning": None,
                "ip_count": len(data["ips"])
            }
            for proto, data in protocol_stats.items()
        ]

        # Ordenar por bytes
        self.results["protocols"].sort(key=lambda x: x["bytes"], reverse=True)

    def _run_detections(self):
        """Executa todas as detecções de segurança"""
        alerts = []

        # 1. Port Scan Detection
        alerts.extend(self._detect_port_scans())

        # 2. Suspicious Ports
        alerts.extend(self._detect_suspicious_ports())

        # 3. ARP Spoofing
        alerts.extend(self._detect_arp_spoofing())

        # 4. DNS Tunneling
        alerts.extend(self._detect_dns_tunneling())

        # 5. Insecure Protocols
        alerts.extend(self._detect_insecure_protocols())

        # 6. IP-MAC Changes (novo)
        alerts.extend(self._detect_ip_mac_changes())

        # 7. External SMB Access (novo)
        alerts.extend(self._detect_external_smb_access())

        # Adicionar timestamp aos alertas
        for alert in alerts:
            if "timestamp" not in alert:
                alert["timestamp"] = datetime.now().isoformat()

        self.results["alerts"] = alerts

    def _detect_port_scans(self):
        """Detecta port scans (SYN scan, Connect scan)"""
        threshold_ports = self.settings.get("thresholds", {}).get("port_scan_min_ports", 20)
        threshold_time = self.settings.get("thresholds", {}).get("port_scan_time_window", 30)

        syn_by_src = defaultdict(lambda: {"ports": set(), "timestamps": []})
        alerts = []

        for pkt in self.packets:
            if TCP in pkt and IP in pkt:
                # Verificar flag SYN (0x02)
                if pkt[TCP].flags & 0x02:  # SYN flag
                    src_ip = pkt[IP].src
                    dst_port = pkt[TCP].dport
                    timestamp = float(pkt.time)

                    syn_by_src[src_ip]["ports"].add(dst_port)
                    syn_by_src[src_ip]["timestamps"].append(timestamp)

        # Analisar cada IP
        for src_ip, data in syn_by_src.items():
            ports = data["ports"]
            timestamps = sorted(data["timestamps"])

            if len(ports) >= threshold_ports:
                duration = timestamps[-1] - timestamps[0]
                if duration <= threshold_time:
                    alerts.append({
                        "severity": "critical",
                        "category": "scan",
                        "title": "Port Scan Detected",
                        "description": f"IP {src_ip} scanned {len(ports)} ports in {duration:.2f} seconds",
                        "ip": src_ip,
                        "details": {
                            "ports_count": len(ports),
                            "duration": round(duration, 2),
                            "ports": sorted(list(ports))[:20]  # Primeiras 20 portas
                        },
                        "recommendation": "Investigate host activity for possible compromise. Block if unauthorized scan."
                    })

        return alerts

    def _detect_suspicious_ports(self):
        """Detecta uso de portas suspeitas conhecidas"""
        alerts = []
        port_usage = {}  # porta -> set de IPs

        for pkt in self.packets:
            if TCP in pkt and IP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                # Verificar porta de origem
                if src_port in self.SUSPICIOUS_PORTS:
                    if src_port not in port_usage:
                        port_usage[src_port] = set()
                    port_usage[src_port].add(src_ip)

                # Verificar porta de destino
                if dst_port in self.SUSPICIOUS_PORTS:
                    if dst_port not in port_usage:
                        port_usage[dst_port] = set()
                    port_usage[dst_port].add(dst_ip)

        # Gerar alertas
        for port, ips in port_usage.items():
            name, severity = self.SUSPICIOUS_PORTS[port]
            for ip in ips:
                alerts.append({
                    "severity": severity,
                    "category": "port",
                    "title": f"Suspicious Port {port}",
                    "description": f"Port {port} ({name}) detected on {ip}",
                    "ip": ip,
                    "details": {
                        "port": port,
                        "port_name": name
                    },
                    "recommendation": f"Investigate traffic on port {port}. This port is commonly associated with malicious activity."
                })

        return alerts

    def _detect_arp_spoofing(self):
        """Detecta ARP spoofing/poisoning"""
        threshold = self.settings.get("thresholds", {}).get("arp_gratuitous_max", 5)

        ip_to_mac = {}
        gratuitous_count = defaultdict(int)
        alerts = []

        for pkt in self.packets:
            if ARP in pkt:
                if pkt[ARP].op == 2:  # ARP Reply
                    src_ip = pkt[ARP].psrc
                    src_mac = pkt[ARP].hwsrc

                    # Verificar conflito IP-MAC
                    if src_ip in ip_to_mac:
                        if ip_to_mac[src_ip] != src_mac:
                            alerts.append({
                                "severity": "critical",
                                "category": "arp",
                                "title": "ARP Spoofing Detected",
                                "description": f"IP {src_ip} changed MAC from {ip_to_mac[src_ip]} to {src_mac}",
                                "ip": src_ip,
                                "details": {
                                    "old_mac": ip_to_mac[src_ip],
                                    "new_mac": src_mac
                                },
                                "recommendation": "Possible ARP spoofing attack. Verify network integrity and check for man-in-the-middle attacks."
                            })

                    ip_to_mac[src_ip] = src_mac

                    # Contar gratuitous ARP (quando pdst == psrc)
                    if pkt[ARP].pdst == pkt[ARP].psrc:
                        gratuitous_count[src_mac] += 1
                        if gratuitous_count[src_mac] == threshold:
                            alerts.append({
                                "severity": "high",
                                "category": "arp",
                                "title": "Gratuitous ARP Flood",
                                "description": f"MAC {src_mac} sent {gratuitous_count[src_mac]} gratuitous ARP packets",
                                "ip": src_ip,
                                "details": {
                                    "mac": src_mac,
                                    "count": gratuitous_count[src_mac]
                                },
                                "recommendation": "Possible ARP poisoning attempt. Monitor this MAC address for suspicious activity."
                            })

        return alerts

    def _detect_dns_tunneling(self):
        """Detecta DNS tunneling baseado em comprimento e entropia"""
        subdomain_threshold = self.settings.get("thresholds", {}).get("dns_subdomain_length", 50)
        entropy_threshold = self.settings.get("thresholds", {}).get("dns_entropy_min", 3.5)

        alerts = []

        for pkt in self.packets:
            if DNS in pkt and IP in pkt:
                if pkt[DNS].qr == 0:  # Query
                    if DNSQR in pkt:
                        try:
                            query = pkt[DNSQR].qname
                            if isinstance(query, bytes):
                                query = query.decode('utf-8', errors='ignore')
                            query = query.rstrip('.')

                            parts = query.split('.')

                            if len(parts) >= 3:
                                subdomain = parts[0]
                                domain = '.'.join(parts[-2:])

                                if len(subdomain) > subdomain_threshold:
                                    entropy = self._calculate_entropy(subdomain)
                                    if entropy > entropy_threshold:
                                        alerts.append({
                                            "severity": "critical",
                                            "category": "dns",
                                            "title": "DNS Tunneling Suspected",
                                            "description": f"Long subdomain ({len(subdomain)} chars) with high entropy ({entropy:.2f})",
                                            "ip": pkt[IP].src,
                                            "details": {
                                                "domain": query,
                                                "subdomain": subdomain,
                                                "subdomain_length": len(subdomain),
                                                "entropy": round(entropy, 2)
                                            },
                                            "recommendation": "Block domain and investigate host for malware. DNS tunneling is commonly used for data exfiltration."
                                        })
                        except Exception:
                            # Ignorar erros de parsing DNS
                            pass

        return alerts

    def _detect_insecure_protocols(self):
        """Detecta uso de protocolos inseguros"""
        alerts = []
        insecure_found = set()

        for pkt in self.packets:
            if TCP in pkt and IP in pkt:
                # FTP (porta 21)
                if (pkt[TCP].dport == 21 or pkt[TCP].sport == 21) and "FTP" not in insecure_found:
                    insecure_found.add("FTP")
                    alerts.append({
                        "severity": "high",
                        "category": "protocol",
                        "title": "Insecure Protocol: FTP",
                        "description": "FTP protocol detected - credentials transmitted in plain text",
                        "ip": pkt[IP].src,
                        "details": {"protocol": "FTP", "port": 21},
                        "recommendation": "Migrate to SFTP or FTPS for secure file transfers."
                    })

                # Telnet (porta 23)
                elif (pkt[TCP].dport == 23 or pkt[TCP].sport == 23) and "Telnet" not in insecure_found:
                    insecure_found.add("Telnet")
                    alerts.append({
                        "severity": "critical",
                        "category": "protocol",
                        "title": "Insecure Protocol: Telnet",
                        "description": "Telnet protocol detected - extremely insecure",
                        "ip": pkt[IP].src,
                        "details": {"protocol": "Telnet", "port": 23},
                        "recommendation": "Replace Telnet with SSH immediately. Telnet transmits all data in clear text."
                    })

        return alerts

    def _detect_ip_mac_changes(self):
        """Detecta mudanças de MAC para um mesmo IP (possível spoofing ou DHCP)"""
        alerts = []
        ip_mac_history = self.results.get("ip_mac_mapping", {})

        for ip, macs in ip_mac_history.items():
            if len(macs) > 1:
                # IP tem múltiplos MACs - possível problema
                is_local = self._is_local_ip(ip)

                if is_local:
                    # IPs locais com múltiplos MACs são mais suspeitos
                    alerts.append({
                        "severity": "high",
                        "category": "mac",
                        "title": "IP with Multiple MAC Addresses",
                        "description": f"Local IP {ip} was seen with {len(macs)} different MAC addresses",
                        "ip": ip,
                        "details": {
                            "mac_addresses": macs,
                            "mac_count": len(macs),
                            "ip_type": "local"
                        },
                        "recommendation": "This may indicate MAC spoofing, ARP poisoning, or a device being replaced. Verify the legitimacy of all MAC addresses."
                    })
                else:
                    # IPs externos podem ter múltiplos MACs devido a roteamento
                    # Alerta de nível mais baixo
                    alerts.append({
                        "severity": "medium",
                        "category": "mac",
                        "title": "External IP with Multiple MAC Addresses",
                        "description": f"External IP {ip} was seen with {len(macs)} different MAC addresses (may be normal routing)",
                        "ip": ip,
                        "details": {
                            "mac_addresses": macs,
                            "mac_count": len(macs),
                            "ip_type": "external"
                        },
                        "recommendation": "This is often normal for external IPs due to routing changes. Monitor if the behavior is unexpected."
                    })

        return alerts

    def _detect_external_smb_access(self):
        """Detecta acesso SMB de IPs externos (potencial ameaça)"""
        alerts = []
        external_smb_ips = set()

        for pkt in self.packets:
            if TCP in pkt and IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                dst_port = pkt[TCP].dport
                src_port = pkt[TCP].sport

                # Verificar se é tráfego SMB
                if dst_port in self.SMB_PORTS or src_port in self.SMB_PORTS:
                    # Verificar se a origem é externa acessando SMB local
                    if not self._is_local_ip(src_ip) and self._is_local_ip(dst_ip):
                        if dst_port in self.SMB_PORTS:
                            external_smb_ips.add((src_ip, dst_ip, "inbound"))

                    # Verificar se destino é externo (dados SMB saindo)
                    if self._is_local_ip(src_ip) and not self._is_local_ip(dst_ip):
                        if dst_port in self.SMB_PORTS:
                            external_smb_ips.add((src_ip, dst_ip, "outbound"))

        # Gerar alertas para cada combinação
        for src_ip, dst_ip, direction in external_smb_ips:
            if direction == "inbound":
                alerts.append({
                    "severity": "critical",
                    "category": "smb",
                    "title": "External IP Accessing SMB",
                    "description": f"External IP {src_ip} is accessing SMB on local host {dst_ip}",
                    "ip": src_ip,
                    "details": {
                        "external_ip": src_ip,
                        "local_target": dst_ip,
                        "direction": "inbound",
                        "ports": list(self.SMB_PORTS)
                    },
                    "recommendation": "SMB should NOT be accessible from external networks. Block SMB ports (445, 139) at the firewall for external traffic. Investigate potential compromise."
                })
            else:
                alerts.append({
                    "severity": "high",
                    "category": "smb",
                    "title": "SMB Traffic to External IP",
                    "description": f"Local host {src_ip} is sending SMB traffic to external IP {dst_ip}",
                    "ip": src_ip,
                    "details": {
                        "local_source": src_ip,
                        "external_target": dst_ip,
                        "direction": "outbound",
                        "ports": list(self.SMB_PORTS)
                    },
                    "recommendation": "SMB traffic to external IPs is unusual and potentially dangerous. This could indicate data exfiltration or compromised host. Investigate immediately."
                })

        return alerts

    def _classify_protocol_risks(self):
        """Classifica o nível de risco dos protocolos detectados"""
        for proto in self.results["protocols"]:
            risk, warning = self.PROTOCOL_RISK.get(proto["name"], ('medium', None))
            proto["risk_level"] = risk
            proto["warning"] = warning

    def _generate_traffic_timeline(self):
        """Gera timeline de tráfego agregado por intervalos de tempo"""
        if not self.packets:
            return

        # Agrupar por intervalos de 10 segundos
        interval = 10
        timeline = defaultdict(lambda: {"bytes": 0, "packets": 0})

        first_time = float(self.packets[0].time)

        for pkt in self.packets:
            timestamp = float(pkt.time)
            # Calcular intervalo
            time_bucket = int((timestamp - first_time) / interval) * interval

            timeline[time_bucket]["bytes"] += len(pkt)
            timeline[time_bucket]["packets"] += 1

        # Converter para lista ordenada
        self.results["traffic_timeline"] = [
            {
                "timestamp": first_time + bucket,
                "bytes": data["bytes"],
                "packets": data["packets"]
            }
            for bucket, data in sorted(timeline.items())
        ]

    def _count_alerts_per_ip(self):
        """Conta alertas por IP"""
        alert_counts = defaultdict(int)

        for alert in self.results["alerts"]:
            if "ip" in alert:
                alert_counts[alert["ip"]] += 1

        # Atualizar contagem nos IPs
        for ip_data in self.results["ips"]:
            ip_data["alert_count"] = alert_counts.get(ip_data["ip"], 0)

    @staticmethod
    def _calculate_entropy(string):
        """
        Calcula a entropia de Shannon de uma string
        Entropia alta indica aleatoriedade (possível malware/tunneling)
        """
        if not string:
            return 0

        counter = Counter(string)
        length = len(string)

        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )

        return entropy

    @staticmethod
    def _is_local_ip(ip_str):
        """Verifica se um IP é privado/local"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False


if __name__ == "__main__":
    # Teste
    import sys

    if len(sys.argv) < 2:
        print("Usage: python pcap_analyzer.py <pcap_file>")
        sys.exit(1)

    analyzer = PCAPAnalyzer(sys.argv[1])
    results = analyzer.analyze()

    print("\n=== SUMMARY ===")
    print(f"Packets: {results['summary']['packet_count']}")
    print(f"Duration: {results['summary']['duration']:.2f}s")
    print(f"IPs: {len(results['ips'])}")
    print(f"Protocols: {len(results['protocols'])}")
    print(f"Alerts: {len(results['alerts'])}")

    print("\n=== ALERTS ===")
    for alert in results['alerts']:
        print(f"[{alert['severity'].upper()}] {alert['title']}: {alert['description']}")
