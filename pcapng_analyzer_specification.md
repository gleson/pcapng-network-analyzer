# 🔍 PCAP Network Analyzer - Especificação Completa do Sistema

## 📋 Visão Geral do Projeto

Sistema web desenvolvido em **Flask** para análise profunda de arquivos `.pcapng` (Wireshark), com foco em:
- Detecção de problemas de rede
- Identificação de vulnerabilidades de segurança
- Análise de protocolos
- Monitoramento de tráfego por IP
- Detecção de ataques e scans

---

## 🎯 PARTE 1: Análises Disponíveis no Sistema

### 1.1 Análises de Segurança

#### 1.1.1 Detecção de Scans de Rede
| Tipo de Scan | Método de Detecção | Criticidade |
|--------------|-------------------|-------------|
| **TCP Connect Scan** | Muitos pacotes SYN+ACK seguidos de RST em curto intervalo | Alta |
| **SYN Scan (Stealth)** | SYN sem completar handshake (SYN → SYN-ACK → RST) | Alta |
| **FIN Scan** | Pacotes com apenas flag FIN definida | Alta |
| **XMAS Scan** | Pacotes com flags URG+PSH+FIN | Alta |
| **NULL Scan** | Pacotes TCP sem flags (tcp.flags == 0x00) | Alta |
| **UDP Scan** | Muitas requisições UDP com respostas ICMP Port Unreachable | Média |
| **Ping Sweep** | Múltiplos ICMP Echo Request para IPs sequenciais | Média |
| **Service Version Scan** | Padrões de sondagem de versão (nmap -sV) | Alta |

**Indicadores:**
- IP enviando SYN para múltiplas portas (>20 portas diferentes)
- Razão SYN/SYN-ACK desproporcional (>3:1)
- Pacotes enviados em intervalos muito curtos (<100ms)
- Conexões sem transferência de dados

#### 1.1.2 Detecção de ARP Spoofing/Poisoning
| Indicador | Descrição | Criticidade |
|-----------|-----------|-------------|
| **ARP Gratuitous excessivo** | Mais de 5 respostas ARP não solicitadas | Alta |
| **Conflito MAC-IP** | Mesmo IP associado a MACs diferentes | Crítica |
| **ARP Flood** | Grande volume de pacotes ARP em curto período | Alta |
| **Mudança de Gateway** | MAC do gateway alterado | Crítica |

#### 1.1.3 Análise DNS
| Problema | Detecção | Criticidade |
|----------|----------|-------------|
| **DNS Tunneling** | Subdomínios muito longos (>50 chars), alta entropia, consultas frequentes | Crítica |
| **DNS Exfiltration** | Volume anormal de consultas TXT, registros grandes | Crítica |
| **DGA (Domain Generation Algorithm)** | Domínios com padrões aleatórios/alta entropia | Alta |
| **DNS Spoofing** | Respostas DNS inconsistentes para mesma consulta | Alta |
| **NXDOMAIN Flood** | Muitas respostas de domínio inexistente | Média |
| **Fast Flux** | Mesmo domínio resolvendo para múltiplos IPs rapidamente | Alta |

#### 1.1.4 Análise SSL/TLS
| Problema | Detecção | Criticidade |
|----------|----------|-------------|
| **Certificado Expirado** | Validade do certificado | Alta |
| **Certificado Self-Signed** | Ausência de cadeia de confiança | Média |
| **TLS Versão Obsoleta** | TLS 1.0, TLS 1.1, SSL 3.0 | Alta |
| **Cipher Suites Fracos** | RC4, DES, MD5, Export ciphers | Alta |
| **Certificate Mismatch** | CN/SAN não corresponde ao host | Alta |
| **SSL Stripping** | Downgrade de HTTPS para HTTP | Crítica |

#### 1.1.5 Portas Suspeitas Conhecidas
| Porta | Nome/Uso Comum | Criticidade |
|-------|----------------|-------------|
| **4444** | Metasploit Default | 🔴 Crítica |
| **666** | Doom Backdoor | 🔴 Crítica |
| **1337** | Leet/Hacker Culture | 🟠 Alta |
| **6666** | IRC Backdoor | 🔴 Crítica |
| **6667** | IRC (pode ser C2) | 🟡 Média |
| **27374** | SubSeven Trojan | 🔴 Crítica |
| **31337** | Back Orifice | 🔴 Crítica |
| **65000** | Várias Backdoors | 🔴 Crítica |
| **5555** | Android ADB | 🟠 Alta |
| **9001** | Tor Default | 🟡 Média |
| **1080** | SOCKS Proxy | 🟡 Média |

> **Regra:** Se qualquer IP utilizar essas portas → Gerar alerta automático com descrição da porta.

#### 1.1.6 Detecção de Ataques
| Ataque | Padrão de Detecção | Criticidade |
|--------|-------------------|-------------|
| **Brute Force SSH/FTP** | Múltiplas conexões com falhas de autenticação | Alta |
| **SYN Flood (DoS)** | Volume massivo de SYN sem ACK | Crítica |
| **ICMP Flood** | Volume massivo de ICMP | Alta |
| **Man-in-the-Middle** | ARP spoofing + interceptação de tráfego | Crítica |
| **SQL Injection** | Padrões SQL em requisições HTTP | Crítica |
| **XSS** | Tags `<script>` em parâmetros HTTP | Alta |
| **Command Injection** | Padrões de comandos shell em HTTP | Crítica |

#### 1.1.6 Análise de Malware/C2
| Indicador | Detecção | Criticidade |
|-----------|----------|-------------|
| **Beaconing** | Conexões periódicas regulares (ex: cada 60s) | Alta |
| **C2 Communication** | Padrões de comunicação suspeitos para IPs externos | Crítica |
| **Data Exfiltration** | Upload de grandes volumes para destinos incomuns | Crítica |
| **Lateral Movement** | Conexões SMB/RDP/WinRM entre hosts internos | Alta |
| **Reverse Shell** | Conexões outbound em portas incomuns | Crítica |

### 1.2 Análises de Rede/Performance

#### 1.2.1 Problemas de Conectividade
| Problema | Detecção |
|----------|----------|
| **Retransmissões TCP** | Alto índice de pacotes retransmitidos |
| **Out-of-Order** | Pacotes fora de sequência |
| **Duplicatas** | Pacotes duplicados |
| **Window Size Zero** | Problemas de buffer/congestionamento |
| **RST Anormais** | Conexões resetadas inesperadamente |

#### 1.2.2 Análise de Latência
| Métrica | Descrição |
|---------|-----------|
| **RTT (Round Trip Time)** | Tempo de ida e volta |
| **Time to First Byte** | Tempo até primeiro byte de resposta |
| **Connection Setup Time** | Tempo do handshake TCP |
| **DNS Resolution Time** | Tempo de resolução DNS |

#### 1.2.3 Análise de Banda
| Métrica | Descrição |
|---------|-----------|
| **Throughput por IP** | Bytes/s de cada IP |
| **Top Talkers** | IPs que mais geram tráfego |
| **Protocolo Distribution** | Percentual de uso por protocolo |
| **Peak Usage** | Picos de utilização |

### 1.3 Análise de Protocolos

#### 1.3.1 Classificação de Risco por Protocolo
| Nível | Protocolos | Descrição |
|-------|------------|-----------|
| 🟢 **Baixo** | DNS, HTTPS, SSH, ICMP, NTP | Protocolos seguros ou de infraestrutura |
| 🟡 **Médio** | TCP genérico, HTTP, IPv6, SMTP, UDP genérico | Requerem atenção, podem expor dados |
| 🔴 **Alto** | FTP, Telnet, ARP, SMBv1, SNMP v1/v2 | Protocolos inseguros, evitar uso |

> **Regra de Exibição:** Na lista de protocolos, exibir badge colorido de acordo com o nível de risco.

#### 1.3.2 Protocolos por Camada
| Camada | Protocolos Analisados |
|--------|----------------------|
| **Layer 2** | Ethernet, ARP, VLAN (802.1Q) |
| **Layer 3** | IPv4, IPv6, ICMP, ICMPv6 |
| **Layer 4** | TCP, UDP, SCTP |
| **Layer 7** | HTTP, HTTPS, DNS, FTP, SSH, Telnet, SMTP, SMB, RDP, DHCP, NTP, SNMP |

#### 1.3.2 Alertas por Protocolo
| Protocolo | Alertas |
|-----------|---------|
| **HTTP** | Métodos suspeitos, status codes anormais, user-agents maliciosos |
| **FTP** | Credenciais em texto claro, comandos suspeitos |
| **Telnet** | Qualquer uso (protocolo inseguro) |
| **SMB** | Versões antigas (SMBv1), tentativas de acesso |
| **SMTP** | Relay aberto, spam indicators |
| **DHCP** | Rogue DHCP server, DHCP starvation |

---

## 🖥️ PARTE 2: Recursos e Telas do Sistema

### 2.1 Arquitetura de Telas

```
┌─────────────────────────────────────────────────────────────┐
│                     MENU PRINCIPAL                          │
├─────────────────────────────────────────────────────────────┤
│  📊 Dashboard  │  📁 Upload  │  🌐 IPs  │  🔧 Configurações │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Tela: Upload e Gerenciamento de Arquivos

#### Funcionalidades:
- Upload de arquivos `.pcap` e `.pcapng`
- Suporte a múltiplos arquivos
- Barra de progresso de upload
- Preview de informações básicas (tamanho, duração, nº pacotes)
- Histórico de arquivos analisados
- Opção de reanálise

#### Campos da Interface:
```
┌─────────────────────────────────────────────────────────────┐
│  📤 UPLOAD DE ARQUIVO PCAPNG                                │
├─────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────┐  │
│  │     Arraste o arquivo aqui ou clique para upload      │  │
│  │              Formatos: .pcap, .pcapng                 │  │
│  │              Tamanho máximo: 500MB                    │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  📋 Arquivos Recentes:                                      │
│  ┌─────────────────┬──────────┬──────────┬────────────────┐ │
│  │ Nome            │ Tamanho  │ Data     │ Ações          │ │
│  ├─────────────────┼──────────┼──────────┼────────────────┤ │
│  │ capture_01.pcap │ 45.2 MB  │ 29/01/26 │ [Ver][Excluir] │ │
│  └─────────────────┴──────────┴──────────┴────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 Tela: Dashboard Principal

#### Layout do Dashboard:
```
┌─────────────────────────────────────────────────────────────────────────┐
│                        📊 DASHBOARD - capture_network.pcapng            │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │ 📦 Pacotes  │  │ 🌐 IPs      │  │ ⚠️ Alertas  │  │ ⏱️ Duração  │     │
│  │   125,432   │  │    47       │  │    12       │  │  00:45:23   │     │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘     │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────┐  ┌─────────────────────────────────┐   │
│  │ 📈 TRÁFEGO POR TEMPO        │  │ 🥧 DISTRIBUIÇÃO DE PROTOCOLOS   │   │
│  │  [Gráfico de linha]         │  │  [Gráfico de pizza]             │   │
│  └─────────────────────────────┘  └─────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ 🚨 ALERTAS DE SEGURANÇA                                         │    │
│  ├─────────────────────────────────────────────────────────────────┤    │
│  │ ● CRÍTICO: Possível Port Scan detectado - 192.168.1.105         │    │
│  │ ● ALTO: DNS Tunneling suspeito - consultas para xyz.tk          │    │
│  │ ● MÉDIO: Certificado TLS expirado - 10.0.0.50                   │    │
│  └─────────────────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────────┐  ┌────────────────────────────────┐ │
│  │ 🌐 TOP IPs POR TRÁFEGO         │  │ 📡 PROTOCOLOS DETECTADOS       │ │
│  ├────────────────────────────────┤  ├────────────────────────────────┤ │
│  │ IP              │ Volume │ ⚠️  │  │ Protocolo │ Pacotes │ Status   │ │
│  │ 192.168.1.1     │ 45MB   │ ✅  │  │ TCP       │ 89,432  │ ✅ OK    │ │
│  │ [Gateway]       │        │     │  │ UDP       │ 23,122  │ ✅ OK    │ │
│  │ 192.168.1.105   │ 12MB   │ ⚠️  │  │ DNS       │ 4,521   │ ⚠️ Alerta│ │
│  │ [Desconhecido]  │        │     │  │ HTTP      │ 8,234   │ ✅ OK    │ │
│  │ 8.8.8.8         │ 2MB    │ ✅  │  │ TLS       │ 12,443  │ ⚠️ Alerta│ │
│  │ [Google DNS]    │        │     │  │ ARP       │ 234     │ ✅ OK    │ │
│  └────────────────────────────────┘  └────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Componentes do Dashboard:

##### Cards de Resumo:
- Total de Pacotes
- IPs Únicos
- Total de Alertas (por criticidade)
- Duração da Captura
- Tamanho Total do Tráfego
- Protocolos Únicos

##### Gráficos:
1. **Tráfego por Tempo** (Line Chart)
   - Eixo X: Timestamp
   - Eixo Y: Bytes/s ou Pacotes/s
   - Filtros: Por IP, Por Protocolo

2. **Distribuição de Protocolos** (Pie/Donut Chart)
   - Percentual por protocolo
   - Interativo (clique para filtrar)

3. **Top Talkers** (Bar Chart)
   - Top 10 IPs por volume
   - Separação: Enviado vs Recebido

4. **Mapa de Conexões** (Network Graph)
   - Visualização de comunicações IP-IP
   - Cores por tipo de protocolo
   - Tamanho do nó por volume

5. **Timeline de Alertas** (Timeline)
   - Alertas ordenados por tempo
   - Filtro por criticidade

### 2.4 Tela: Lista de IPs

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           🌐 GERENCIAMENTO DE IPs                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  🔍 Buscar: [________________] [Filtrar ▼] [Exportar CSV]                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ IP Address    │ Descrição       │ Tipo      │ Tráfego │ Alertas │ ⚙️ │    │
│  ├───────────────┼─────────────────┼───────────┼─────────┼─────────┼────┤    │
│  │ 192.168.1.1   │ Gateway/Router  │ 🏠 Local  │ 45.2MB  │ 0       │ ✏️ │    │
│  │               │ ⭐ Confiável    │           │         │         │    │    │
│  ├───────────────┼─────────────────┼───────────┼─────────┼─────────┼────┤    │
│  │ 192.168.1.50  │ Servidor Web    │ 🏠 Local  │ 23.1MB  │ 1 ⚠️    │ ✏️ │    │
│  │               │ ⭐ Confiável    │           │         │         │    │    │
│  ├───────────────┼─────────────────┼───────────┼─────────┼─────────┼────┤    │
│  │ 192.168.1.105 │ --              │ 🏠 Local  │ 12.4MB  │ 3 🔴    │ ✏️ │    │
│  │               │ ❓ Desconhecido │           │         │         │    │    │
│  ├───────────────┼─────────────────┼───────────┼─────────┼─────────┼────┤    │
│  │ 13.107.42.14  │ Microsoft Update│ 🌍 Externo│ 8.2MB   │ 0       │ ✏️ │    │
│  │               │ ⭐ Confiável    │ (Range)   │         │         │    │    │
│  ├───────────────┼─────────────────┼───────────┼─────────┼─────────┼────┤    │
│  │ 185.220.101.1 │ --              │ 🌍 Externo│ 0.5MB   │ 2 🔴    │ ✏️ │    │
│  │               │ 🚫 Blacklist    │ TOR Exit  │         │         │    │    │
│  └───────────────┴─────────────────┴───────────┴─────────┴─────────┴────┘    │
├─────────────────────────────────────────────────────────────────────────────┤
│  📊 Resumo: 47 IPs | 12 Locais | 35 Externos | 5 Confiáveis | 3 Blacklist  │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Funcionalidades:
- Lista paginada de todos os IPs
- Busca e filtros avançados
- Edição inline de descrições
- Marcação como confiável/suspeito
- Visualização de alertas por IP
- Detalhes expandidos ao clicar
- Exportação para CSV/JSON

### 2.5 Tela: Detalhes do IP

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  🔍 DETALHES DO IP: 192.168.1.105                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ INFORMAÇÕES BÁSICAS                                                  │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ Descrição: [_____________________] [Salvar]                         │    │
│  │ Status: ○ Confiável  ● Neutro  ○ Suspeito                           │    │
│  │ MAC Address: AA:BB:CC:DD:EE:FF                                      │    │
│  │ Hostname: desktop-pc105 (via DHCP/NetBIOS)                          │    │
│  │ Primeira aparição: 29/01/2026 10:23:45                              │    │
│  │ Última aparição: 29/01/2026 11:08:32                                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 📊 ESTATÍSTICAS DE TRÁFEGO                                          │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ Pacotes Enviados: 23,456    │    Pacotes Recebidos: 18,234          │    │
│  │ Bytes Enviados: 8.2 MB      │    Bytes Recebidos: 4.1 MB            │    │
│  │ Conexões TCP: 145           │    Sessões UDP: 34                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 🚨 ALERTAS (3)                                                      │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ 🔴 CRÍTICO | Port Scan detectado - 47 portas em 30 segundos         │    │
│  │            | 10:45:12 - 10:45:42                                    │    │
│  │ 🔴 CRÍTICO | Tentativa de conexão a IP blacklist                    │    │
│  │            | 10:52:33                                               │    │
│  │ 🟡 MÉDIO   | Volume de tráfego anormal                              │    │
│  │            | 11:02:00                                               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 🔗 CONEXÕES COM OUTROS IPs                                          │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ Destino          │ Porta  │ Protocolo │ Pacotes │ Bytes             │    │
│  │ 192.168.1.1      │ 53     │ DNS       │ 234     │ 45KB              │    │
│  │ 8.8.8.8          │ 443    │ HTTPS     │ 1,234   │ 2.3MB             │    │
│  │ 185.220.101.1    │ 9001   │ TCP       │ 45      │ 12KB   🚨         │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 📈 GRÁFICO DE TRÁFEGO NO TEMPO                                      │    │
│  │ [===== Gráfico de linha do tráfego deste IP =====]                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.6 Tela: Gerenciamento de Ranges de IP

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      📋 GERENCIAMENTO DE RANGES DE IP                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  [+ Adicionar Novo Range]                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ RANGES CADASTRADOS                                                   │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ Range CIDR        │ Descrição          │ Confiável │ Ações          │    │
│  ├───────────────────┼────────────────────┼───────────┼────────────────┤    │
│  │ 192.168.1.0/24    │ Rede Local         │ ⭐ Sim    │ [✏️] [🗑️]      │    │
│  │ 10.0.0.0/8        │ Rede Interna       │ ⭐ Sim    │ [✏️] [🗑️]      │    │
│  │ 13.64.0.0/11      │ Microsoft Azure    │ ⭐ Sim    │ [✏️] [🗑️]      │    │
│  │ 13.104.0.0/14     │ Microsoft Update   │ ⭐ Sim    │ [✏️] [🗑️]      │    │
│  │ 20.33.0.0/16      │ Microsoft 365      │ ⭐ Sim    │ [✏️] [🗑️]      │    │
│  │ 8.8.8.0/24        │ Google DNS         │ ⭐ Sim    │ [✏️] [🗑️]      │    │
│  │ 1.1.1.0/24        │ Cloudflare DNS     │ ⭐ Sim    │ [✏️] [🗑️]      │    │
│  │ 185.220.100.0/22  │ TOR Exit Nodes     │ 🚫 Não   │ [✏️] [🗑️]      │    │
│  └───────────────────┴────────────────────┴───────────┴────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Modal: Adicionar/Editar Range
```
┌─────────────────────────────────────────────────┐
│  ➕ Adicionar Range de IP                       │
├─────────────────────────────────────────────────┤
│  Range (CIDR): [192.168.0.0/16_________]        │
│                                                 │
│  Descrição:    [Rede Corporativa_______]        │
│                                                 │
│  Status:       ○ Confiável                      │
│                ○ Neutro                         │
│                ○ Suspeito/Blacklist             │
│                                                 │
│  Notas:        [_________________________]      │
│                [_________________________]      │
│                                                 │
│           [Cancelar]  [💾 Salvar]               │
└─────────────────────────────────────────────────┘
```

### 2.7 Tela: Lista de Protocolos

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        📡 ANÁLISE DE PROTOCOLOS                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Protocolo │ Pacotes  │ Bytes     │ % Total │ Status    │ Alertas   │    │
│  ├───────────┼──────────┼───────────┼─────────┼───────────┼───────────┤    │
│  │ TCP       │ 89,432   │ 125.4 MB  │ 71.2%   │ ✅ Normal │ 0         │    │
│  │ UDP       │ 23,122   │ 28.3 MB   │ 18.5%   │ ✅ Normal │ 0         │    │
│  │ HTTPS     │ 45,234   │ 89.2 MB   │ 36.1%   │ ⚠️ Alerta │ 2         │    │
│  │           │          │           │         │ TLS 1.0   │           │    │
│  │ HTTP      │ 8,234    │ 12.1 MB   │ 6.6%    │ ⚠️ Alerta │ 1         │    │
│  │           │          │           │         │ Cleartext │           │    │
│  │ DNS       │ 4,521    │ 1.2 MB    │ 3.6%    │ 🔴 Crítico│ 3         │    │
│  │           │          │           │         │ Tunneling │           │    │
│  │ ARP       │ 234      │ 0.01 MB   │ 0.2%    │ ✅ Normal │ 0         │    │
│  │ ICMP      │ 456      │ 0.05 MB   │ 0.3%    │ ✅ Normal │ 0         │    │
│  │ SSH       │ 1,234    │ 2.3 MB    │ 1.5%    │ ✅ Normal │ 0         │    │
│  │ FTP       │ 89       │ 0.2 MB    │ 0.1%    │ 🔴 Crítico│ 1         │    │
│  │           │          │           │         │ Cleartext │           │    │
│  │ Telnet    │ 12       │ 0.001 MB  │ 0.01%   │ 🔴 Crítico│ 1         │    │
│  │           │          │           │         │ Inseguro  │           │    │
│  │ SMB       │ 567      │ 3.4 MB    │ 2.2%    │ ⚠️ Alerta │ 1         │    │
│  │           │          │           │         │ SMBv1     │           │    │
│  └───────────┴──────────┴───────────┴─────────┴───────────┴───────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.8 Tela: Detalhes do Protocolo

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  📡 DETALHES DO PROTOCOLO: DNS                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ ESTATÍSTICAS GERAIS                                                  │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ Total de Pacotes: 4,521      │    Queries: 2,345                    │    │
│  │ Total de Bytes: 1.2 MB       │    Responses: 2,176                  │    │
│  │ Servidores DNS usados: 3     │    Domínios únicos: 234              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 🚨 ALERTAS DNS (3)                                                  │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ 🔴 CRÍTICO | DNS Tunneling Suspeito                                 │    │
│  │            | Domínio: a7f8c9d2e3b4.malware.tk                       │    │
│  │            | Subdomínio com 45 caracteres, alta entropia            │    │
│  │ 🔴 CRÍTICO | Possível DGA                                           │    │
│  │            | 23 domínios com padrão aleatório detectados            │    │
│  │ 🟡 MÉDIO   | NXDOMAIN excessivo                                     │    │
│  │            | 45 respostas NXDOMAIN em 5 minutos                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 📊 TOP DOMÍNIOS CONSULTADOS                                         │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ Domínio                      │ Queries │ Status                     │    │
│  │ google.com                   │ 234     │ ✅ Normal                  │    │
│  │ microsoft.com                │ 123     │ ✅ Normal                  │    │
│  │ a7f8c9d2e3b4.malware.tk     │ 89      │ 🔴 Suspeito               │    │
│  │ facebook.com                 │ 67      │ ✅ Normal                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 🖥️ SERVIDORES DNS UTILIZADOS                                        │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ IP            │ Descrição    │ Queries │ Status                     │    │
│  │ 8.8.8.8       │ Google DNS   │ 1,234   │ ✅ Confiável              │    │
│  │ 192.168.1.1   │ Gateway      │ 987     │ ✅ Confiável              │    │
│  │ 1.1.1.1       │ Cloudflare   │ 124     │ ✅ Confiável              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.9 Tela: Alertas de Segurança

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        🚨 ALERTAS DE SEGURANÇA                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  Filtros: [Todos ▼] [Crítico ☑] [Alto ☑] [Médio ☑] [Baixo ☐]              │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 🔴 CRÍTICO | Port Scan Detectado                        [Expandir]  │    │
│  │ ──────────────────────────────────────────────────────────────────  │    │
│  │ Timestamp: 29/01/2026 10:45:12                                      │    │
│  │ IP Origem: 192.168.1.105                                            │    │
│  │ Detalhes: 47 portas escaneadas em 30 segundos                       │    │
│  │ Portas: 21, 22, 23, 25, 80, 443, 445, 3389, ...                     │    │
│  │ Tipo: TCP SYN Scan (Half-open)                                      │    │
│  │ Recomendação: Verificar atividade do host, possível comprometimento │    │
│  │                                                              [📋 Ver Pacotes] │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 🔴 CRÍTICO | DNS Tunneling Suspeito                     [Expandir]  │    │
│  │ ──────────────────────────────────────────────────────────────────  │    │
│  │ Timestamp: 29/01/2026 10:52:33                                      │    │
│  │ IP Origem: 192.168.1.105                                            │    │
│  │ Domínio: a7f8c9d2e3b4a5c6d7e8f9.malware.tk                         │    │
│  │ Indicadores: Subdomínio com 35 chars, entropia: 4.2                 │    │
│  │ Recomendação: Bloquear domínio, investigar malware no host          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 🟠 ALTO | Certificado TLS Expirado                      [Expandir]  │    │
│  │ ──────────────────────────────────────────────────────────────────  │    │
│  │ Timestamp: 29/01/2026 11:02:15                                      │    │
│  │ Servidor: 10.0.0.50:443                                             │    │
│  │ CN: internal-server.local                                           │    │
│  │ Expirado em: 15/01/2026 (14 dias atrás)                            │    │
│  │ Recomendação: Renovar certificado imediatamente                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 🟡 MÉDIO | Protocolo Inseguro Detectado                 [Expandir]  │    │
│  │ ──────────────────────────────────────────────────────────────────  │    │
│  │ Protocolo: FTP (porta 21)                                           │    │
│  │ IPs envolvidos: 192.168.1.10 → 192.168.1.20                        │    │
│  │ Credenciais em texto claro detectadas                               │    │
│  │ Recomendação: Migrar para SFTP ou FTPS                              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.10 Tela: Configurações

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ⚙️ CONFIGURAÇÕES                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 📊 THRESHOLDS DE DETECÇÃO                                           │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ Port Scan - Mínimo de portas: [20____]                              │    │
│  │ Port Scan - Janela de tempo: [30____] segundos                      │    │
│  │ ARP Spoofing - Gratuitous máximo: [5_____]                          │    │
│  │ DNS Tunneling - Comprimento subdomínio: [50____] chars              │    │
│  │ DNS Tunneling - Entropia mínima: [3.5___]                           │    │
│  │ Beaconing - Intervalo regular: [60____] segundos                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 🌐 INTEGRAÇÃO THREAT INTELLIGENCE                                   │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ ☑ AbuseIPDB API Key: [************************]                     │    │
│  │ ☑ Usar IPsum (GitHub blacklist)                                     │    │
│  │ ☐ VirusTotal API Key: [________________________]                    │    │
│  │ ☑ Verificar IPs externos automaticamente                            │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 📁 ARMAZENAMENTO                                                    │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ Diretório de uploads: [/var/pcap-analyzer/uploads___]               │    │
│  │ Manter arquivos por: [30____] dias                                  │    │
│  │ Tamanho máximo upload: [500___] MB                                  │    │
│  │ [🗑️ Limpar arquivos antigos]                                        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 🎨 INTERFACE                                                        │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ Tema: ○ Claro  ● Escuro  ○ Sistema                                  │    │
│  │ Itens por página: [25____]                                          │    │
│  │ Atualização automática dashboard: ☑ [30____] segundos               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│                              [💾 Salvar Configurações]                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.11 Tela: Visualizador de Pacotes

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        📦 VISUALIZADOR DE PACOTES                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  Filtro: [ip.src == 192.168.1.105________________________] [Aplicar]       │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ # │ Tempo    │ Origem         │ Destino        │ Proto│ Info       │    │
│  ├───┼──────────┼────────────────┼────────────────┼──────┼────────────┤    │
│  │ 1 │ 0.000000 │ 192.168.1.105  │ 192.168.1.1    │ TCP  │ SYN [22]   │    │
│  │ 2 │ 0.000234 │ 192.168.1.1    │ 192.168.1.105  │ TCP  │ RST,ACK    │    │
│  │ 3 │ 0.001002 │ 192.168.1.105  │ 192.168.1.1    │ TCP  │ SYN [23]   │    │
│  │ 4 │ 0.001456 │ 192.168.1.1    │ 192.168.1.105  │ TCP  │ RST,ACK    │    │
│  │ 5 │ 0.002100 │ 192.168.1.105  │ 192.168.1.1    │ TCP  │ SYN [25]   │    │
│  │ ▼ │ ...      │ ...            │ ...            │ ...  │ ...        │    │
│  └───┴──────────┴────────────────┴────────────────┴──────┴────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ DETALHES DO PACOTE #1                                               │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ ▼ Ethernet II                                                       │    │
│  │   Src: aa:bb:cc:dd:ee:ff    Dst: 11:22:33:44:55:66                 │    │
│  │ ▼ Internet Protocol Version 4                                       │    │
│  │   Src: 192.168.1.105        Dst: 192.168.1.1                       │    │
│  │   TTL: 64                   Protocol: TCP                           │    │
│  │ ▼ Transmission Control Protocol                                     │    │
│  │   Src Port: 45234           Dst Port: 22                            │    │
│  │   Flags: SYN                Seq: 0                                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ HEX DUMP                                                            │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ 0000  aa bb cc dd ee ff 11 22 33 44 55 66 08 00 45 00   │    │
│  │ 0010  00 3c 1c 46 40 00 40 06 b1 e6 c0 a8 01 69 c0 a8   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.12 Tela: Relatórios

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          📄 GERAÇÃO DE RELATÓRIOS                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ TIPO DE RELATÓRIO                                                   │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ ○ Relatório Executivo (Resumo de alertas e recomendações)           │    │
│  │ ● Relatório Técnico Completo                                        │    │
│  │ ○ Relatório de Compliance (Protocolos inseguros)                    │    │
│  │ ○ Lista de IPs e Tráfego                                            │    │
│  │ ○ Relatório de Alertas                                              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ SEÇÕES A INCLUIR                                                    │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ ☑ Resumo Executivo          ☑ Estatísticas Gerais                   │    │
│  │ ☑ Lista de IPs              ☑ Análise de Protocolos                 │    │
│  │ ☑ Alertas de Segurança      ☑ Recomendações                         │    │
│  │ ☐ Dump de Pacotes           ☑ Gráficos                              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ FORMATO DE SAÍDA                                                    │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ ○ PDF    ● HTML    ○ JSON    ○ CSV                                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│                      [📥 Gerar e Baixar Relatório]                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ PARTE 3: Tecnologias e Arquitetura

### 3.1 Stack Tecnológico

#### Backend
```
┌─────────────────────────────────────────────────────────┐
│ BACKEND                                                  │
├─────────────────────────────────────────────────────────┤
│ Framework:      Flask 3.x                                │
│ Python:         3.11+                                    │
│ WSGI Server:    Gunicorn                                 │
│ Task Queue:     Celery + Redis                           │
│ Database:       SQLite (dev) / PostgreSQL (prod)         │
│ ORM:            SQLAlchemy                               │
└─────────────────────────────────────────────────────────┘
```

#### Bibliotecas de Análise PCAP
```
┌─────────────────────────────────────────────────────────┐
│ ANÁLISE DE PACOTES                                      │
├─────────────────────────────────────────────────────────┤
│ Scapy:          Análise e parsing de pacotes            │
│ pyshark:        Interface Python para tshark            │
│ dpkt:           Parsing de pacotes (alternativa leve)   │
│ python-magic:   Detecção de tipo de arquivo             │
└─────────────────────────────────────────────────────────┘
```

#### Frontend
```
┌─────────────────────────────────────────────────────────┐
│ FRONTEND                                                 │
├─────────────────────────────────────────────────────────┤
│ Templates:      Jinja2                                   │
│ CSS Framework:  Bootstrap 5 / Tailwind CSS              │
│ Gráficos:       Chart.js / Plotly.js                    │
│ Network Graph:  vis.js / D3.js                          │
│ DataTables:     DataTables.js (tabelas interativas)     │
│ Icons:          Font Awesome / Heroicons                │
└─────────────────────────────────────────────────────────┘
```

#### Threat Intelligence
```
┌─────────────────────────────────────────────────────────┐
│ THREAT INTELLIGENCE                                      │
├─────────────────────────────────────────────────────────┤
│ AbuseIPDB:      API para verificar reputação de IPs     │
│ IPsum:          Lista diária de IPs maliciosos (GitHub) │
│ Spamhaus:       Listas de bloqueio                      │
│ VirusTotal:     (Opcional) Análise de hashes/URLs       │
│ MaxMind GeoIP:  Geolocalização de IPs                   │
└─────────────────────────────────────────────────────────┘
```

### 3.2 Estrutura de Diretórios

```
pcap-analyzer/
├── app/
│   ├── __init__.py              # Factory da aplicação
│   ├── config.py                # Configurações
│   ├── models/
│   │   ├── __init__.py
│   │   ├── capture.py           # Modelo de captura
│   │   ├── ip_address.py        # Modelo de IPs
│   │   ├── ip_range.py          # Modelo de ranges
│   │   ├── alert.py             # Modelo de alertas
│   │   └── protocol_stats.py    # Estatísticas de protocolos
│   ├── services/
│   │   ├── __init__.py
│   │   ├── pcap_parser.py       # Parser de arquivos pcapng
│   │   ├── analyzer/
│   │   │   ├── __init__.py
│   │   │   ├── base.py          # Classe base de análise
│   │   │   ├── scan_detector.py # Detecção de scans
│   │   │   ├── arp_analyzer.py  # Análise ARP
│   │   │   ├── dns_analyzer.py  # Análise DNS
│   │   │   ├── tls_analyzer.py  # Análise TLS/SSL
│   │   │   ├── traffic_analyzer.py # Análise de tráfego
│   │   │   └── malware_detector.py # Detecção de malware/C2
│   │   ├── threat_intel.py      # Integração com threat intel
│   │   └── report_generator.py  # Geração de relatórios
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── main.py              # Rotas principais
│   │   ├── upload.py            # Upload de arquivos
│   │   ├── dashboard.py         # Dashboard
│   │   ├── ips.py               # Gerenciamento de IPs
│   │   ├── protocols.py         # Análise de protocolos
│   │   ├── alerts.py            # Alertas
│   │   ├── packets.py           # Visualizador de pacotes
│   │   ├── settings.py          # Configurações
│   │   └── api.py               # API REST
│   ├── templates/
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   ├── upload.html
│   │   ├── ips/
│   │   │   ├── list.html
│   │   │   ├── detail.html
│   │   │   └── ranges.html
│   │   ├── protocols/
│   │   │   ├── list.html
│   │   │   └── detail.html
│   │   ├── alerts/
│   │   │   └── list.html
│   │   ├── packets/
│   │   │   └── viewer.html
│   │   ├── reports/
│   │   │   └── generate.html
│   │   └── settings.html
│   └── static/
│       ├── css/
│       ├── js/
│       └── img/
├── tasks/
│   ├── __init__.py
│   └── analysis.py              # Tasks Celery para análise
├── migrations/                  # Migrações do banco
├── tests/                       # Testes
├── uploads/                     # Arquivos uploadados
├── requirements.txt
├── docker-compose.yml
├── Dockerfile
└── run.py
```

### 3.3 Modelos de Dados

#### Capture (Arquivo PCAPNG)
```python
class Capture:
    id: int
    filename: str
    original_filename: str
    file_path: str
    file_size: int  # bytes
    file_hash: str  # SHA256
    packet_count: int
    duration: float  # segundos
    start_time: datetime
    end_time: datetime
    status: str  # 'uploading', 'analyzing', 'completed', 'error'
    created_at: datetime
    analyzed_at: datetime
```

#### IPAddress
```python
class IPAddress:
    id: int
    capture_id: int
    ip_address: str
    ip_version: int  # 4 ou 6
    mac_address: str
    hostname: str  # via DNS reverso ou NetBIOS
    description: str  # definido pelo usuário
    is_trusted: bool
    is_local: bool
    is_external: bool
    packets_sent: int
    packets_received: int
    bytes_sent: int
    bytes_received: int
    first_seen: datetime
    last_seen: datetime
    alert_count: int
    threat_score: int  # 0-100
    geolocation: JSON  # {country, city, lat, lon}
```

#### IPRange
```python
class IPRange:
    id: int
    cidr: str  # ex: "192.168.1.0/24"
    description: str
    is_trusted: bool
    is_local: bool
    notes: str
    created_at: datetime
```

#### Alert
```python
class Alert:
    id: int
    capture_id: int
    ip_address_id: int
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    category: str  # 'scan', 'malware', 'protocol', 'arp', 'dns', 'tls'
    title: str
    description: str
    details: JSON
    recommendation: str
    timestamp: datetime
    packet_numbers: JSON  # lista de pacotes relacionados
    is_acknowledged: bool
```

#### ProtocolStats
```python
class ProtocolStats:
    id: int
    capture_id: int
    protocol_name: str
    layer: int  # 2, 3, 4, 7
    packet_count: int
    byte_count: int
    percentage: float
    has_alerts: bool
    details: JSON
```

### 3.4 Algoritmos de Detecção

#### Detecção de Port Scan
```python
def detect_port_scan(packets, threshold_ports=20, threshold_time=30):
    """
    Detecta port scan analisando:
    1. IP enviando SYN para múltiplas portas
    2. Alta razão SYN/SYN-ACK
    3. Curto intervalo de tempo
    """
    syn_by_src = defaultdict(list)
    
    for pkt in packets:
        if TCP in pkt and pkt[TCP].flags == 'S':  # SYN flag
            syn_by_src[pkt[IP].src].append({
                'dst_ip': pkt[IP].dst,
                'dst_port': pkt[TCP].dport,
                'timestamp': pkt.time
            })
    
    alerts = []
    for src_ip, syns in syn_by_src.items():
        # Agrupar por janela de tempo
        windows = group_by_time_window(syns, threshold_time)
        for window in windows:
            unique_ports = len(set(s['dst_port'] for s in window))
            if unique_ports >= threshold_ports:
                alerts.append({
                    'type': 'port_scan',
                    'severity': 'critical',
                    'src_ip': src_ip,
                    'ports_scanned': unique_ports,
                    'duration': window[-1]['timestamp'] - window[0]['timestamp']
                })
    
    return alerts
```

#### Detecção de DNS Tunneling
```python
import math
from collections import Counter

def calculate_entropy(string):
    """Calcula entropia de Shannon"""
    if not string:
        return 0
    counter = Counter(string)
    length = len(string)
    return -sum((count/length) * math.log2(count/length) 
                for count in counter.values())

def detect_dns_tunneling(packets, subdomain_threshold=50, entropy_threshold=3.5):
    """
    Detecta DNS tunneling analisando:
    1. Comprimento anormal de subdomínios
    2. Alta entropia (caracteres aleatórios)
    3. Volume de queries para mesmo domínio
    """
    alerts = []
    domain_queries = defaultdict(list)
    
    for pkt in packets:
        if DNSQR in pkt:
            query = pkt[DNSQR].qname.decode()
            parts = query.split('.')
            
            # Analisar subdomínio (primeira parte)
            if len(parts) > 2:
                subdomain = parts[0]
                root_domain = '.'.join(parts[-3:-1])
                
                domain_queries[root_domain].append({
                    'subdomain': subdomain,
                    'full_query': query,
                    'timestamp': pkt.time
                })
                
                # Verificar comprimento
                if len(subdomain) > subdomain_threshold:
                    entropy = calculate_entropy(subdomain)
                    if entropy > entropy_threshold:
                        alerts.append({
                            'type': 'dns_tunneling',
                            'severity': 'critical',
                            'domain': query,
                            'subdomain_length': len(subdomain),
                            'entropy': entropy
                        })
    
    return alerts
```

#### Detecção de ARP Spoofing
```python
def detect_arp_spoofing(packets, gratuitous_threshold=5):
    """
    Detecta ARP spoofing analisando:
    1. Respostas ARP não solicitadas (gratuitous)
    2. Conflitos IP-MAC
    3. Mudanças de MAC para mesmo IP
    """
    ip_to_mac = {}
    gratuitous_count = defaultdict(int)
    alerts = []
    
    for pkt in packets:
        if ARP in pkt:
            if pkt[ARP].op == 2:  # ARP Reply
                src_ip = pkt[ARP].psrc
                src_mac = pkt[ARP].hwsrc
                
                # Verificar conflito
                if src_ip in ip_to_mac:
                    if ip_to_mac[src_ip] != src_mac:
                        alerts.append({
                            'type': 'arp_spoofing',
                            'severity': 'critical',
                            'ip': src_ip,
                            'old_mac': ip_to_mac[src_ip],
                            'new_mac': src_mac,
                            'description': f'MAC changed for IP {src_ip}'
                        })
                
                ip_to_mac[src_ip] = src_mac
                
                # Contar gratuitous ARP
                if pkt[ARP].pdst == pkt[ARP].psrc:
                    gratuitous_count[src_mac] += 1
                    if gratuitous_count[src_mac] == gratuitous_threshold:
                        alerts.append({
                            'type': 'gratuitous_arp_flood',
                            'severity': 'high',
                            'mac': src_mac,
                            'count': gratuitous_count[src_mac]
                        })
    
    return alerts
```

#### Detecção de Portas Suspeitas
```python
# Portas conhecidas como maliciosas ou suspeitas
SUSPICIOUS_PORTS = {
    4444: ('Metasploit Default', 'critical'),
    666: ('Doom Backdoor', 'critical'),
    1337: ('Leet/Elite', 'high'),
    6666: ('IRC Backdoor', 'critical'),
    6667: ('IRC (possível C2)', 'medium'),
    27374: ('SubSeven Trojan', 'critical'),
    31337: ('Back Orifice', 'critical'),
    65000: ('Várias Backdoors', 'critical'),
    5555: ('Android ADB', 'high'),
    9001: ('Tor Default', 'medium'),
    1080: ('SOCKS Proxy', 'medium'),
}

def detect_suspicious_ports(packets):
    """
    Detecta uso de portas conhecidamente suspeitas
    """
    alerts = []
    port_usage = defaultdict(set)  # porta -> set de IPs
    
    for pkt in packets:
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            if src_port in SUSPICIOUS_PORTS:
                port_usage[src_port].add(src_ip)
            if dst_port in SUSPICIOUS_PORTS:
                port_usage[dst_port].add(dst_ip)
    
    for port, ips in port_usage.items():
        name, severity = SUSPICIOUS_PORTS[port]
        for ip in ips:
            alerts.append({
                'type': 'suspicious_port',
                'severity': severity,
                'ip': ip,
                'port': port,
                'port_name': name,
                'description': f'Porta suspeita {port} ({name}) detectada em {ip}'
            })
    
    return alerts
```

#### Classificação de Risco de Protocolos
```python
# Classificação de risco por protocolo
PROTOCOL_RISK = {
    # Baixo risco (verde)
    'DNS': ('low', None),
    'HTTPS': ('low', None),
    'SSH': ('low', None),
    'ICMP': ('low', None),
    'NTP': ('low', None),
    'DHCP': ('low', None),
    
    # Médio risco (amarelo)
    'TCP': ('medium', None),
    'UDP': ('medium', None),
    'HTTP': ('medium', 'Tráfego não criptografado - dados podem ser interceptados'),
    'SMTP': ('medium', 'Verificar se usa TLS/STARTTLS'),
    'IPv6': ('medium', None),
    
    # Alto risco (vermelho)
    'FTP': ('high', 'Protocolo inseguro - credenciais em texto plano'),
    'Telnet': ('high', 'Protocolo extremamente inseguro - evitar uso'),
    'ARP': ('high', 'Monitorar para detectar spoofing'),
    'SMBv1': ('high', 'Versão obsoleta com vulnerabilidades conhecidas'),
    'SNMP': ('high', 'Verificar se usa v3 com autenticação'),
}

def classify_protocols(protocol_stats):
    """
    Classifica protocolos encontrados por nível de risco
    """
    classified = []
    
    for proto_name, stats in protocol_stats.items():
        risk_level, warning = PROTOCOL_RISK.get(proto_name, ('medium', None))
        
        classified.append({
            'name': proto_name,
            'packets': stats['packets'],
            'bytes': stats['bytes'],
            'risk': risk_level,
            'warning': warning
        })
    
    return sorted(classified, key=lambda x: x['bytes'], reverse=True)
```

---

## 📝 PARTE 4: Prompt de Desenvolvimento

### Prompt Completo para Criar o Sistema

```
Você é um desenvolvedor Python especializado em segurança de redes e análise de tráfego.
Desenvolva um sistema web completo em Flask para análise de arquivos .pcapng do Wireshark.

## REQUISITOS FUNCIONAIS:

### 1. Upload e Gerenciamento de Arquivos
- Aceitar arquivos .pcap e .pcapng até 500MB
- Processar arquivos em background usando Celery
- Manter histórico de arquivos analisados
- Permitir reanálise

### 2. Dashboard Principal
- Cards com métricas: pacotes, IPs únicos, alertas, duração
- Gráfico de tráfego por tempo (Chart.js)
- Distribuição de protocolos (gráfico de pizza)
- Lista de alertas recentes por criticidade
- Top IPs por tráfego
- Lista de protocolos com status

### 3. Gerenciamento de IPs
- Lista paginada de todos os IPs encontrados
- Campos editáveis: descrição, status de confiança
- Classificação automática: local/externo
- Verificação de reputação via AbuseIPDB
- Detalhes expandidos: estatísticas, conexões, alertas
- Geolocalização de IPs externos

### 4. Gerenciamento de Ranges de IP
- CRUD de ranges em notação CIDR
- Descrição customizada (ex: "Microsoft Update", "Rede Local")
- Marcação como confiável/neutro/suspeito
- Aplicação automática quando IP do range é detectado
- Ranges pré-configurados para provedores conhecidos

### 5. Análise de Protocolos
- Lista de todos os protocolos detectados
- Estatísticas por protocolo (pacotes, bytes, %)
- Alertas específicos por protocolo:
  * TLS: versões obsoletas, certificados expirados
  * HTTP: credenciais em texto claro
  * DNS: tunneling, DGA
  * FTP/Telnet: protocolos inseguros
  * SMB: versões antigas

### 6. Detecção de Ameaças
Implementar detecção de:
- Port Scan (TCP Connect, SYN, FIN, XMAS, NULL, UDP)
- ARP Spoofing/Poisoning
- DNS Tunneling e DGA
- Certificados TLS problemáticos
- Beaconing (comunicação C2)
- Brute force (SSH, FTP)
- Protocolos inseguros

### 7. Sistema de Alertas
- Categorias: scan, malware, protocol, arp, dns, tls
- Severidades: critical, high, medium, low, info
- Detalhes técnicos e recomendações
- Links para pacotes relacionados
- Filtros por categoria e severidade

### 8. Visualizador de Pacotes
- Lista de pacotes com filtros (estilo Wireshark)
- Detalhes em camadas (Ethernet, IP, TCP/UDP, Application)
- Hex dump
- Seguir conversação TCP/UDP

### 9. Relatórios
- Formatos: PDF, HTML, JSON, CSV
- Tipos: Executivo, Técnico, Compliance
- Seções selecionáveis

### 10. Configurações
- Thresholds de detecção customizáveis
- APIs de threat intelligence
- Preferências de interface

## REQUISITOS TÉCNICOS:

### Backend
- Flask 3.x com Blueprints
- SQLAlchemy + Flask-Migrate
- Celery + Redis para processamento
- Scapy para parsing de pacotes

### Frontend
- Jinja2 templates
- Bootstrap 5 ou Tailwind CSS
- Chart.js para gráficos
- DataTables para tabelas
- vis.js para grafos de rede

### Segurança
- Validação de uploads (tipo, tamanho)
- Sanitização de inputs
- CSRF protection
- Rate limiting

### Banco de Dados
Criar modelos para:
- Capture (arquivo pcapng)
- IPAddress (IPs encontrados)
- IPRange (ranges configurados)
- Alert (alertas detectados)
- ProtocolStats (estatísticas por protocolo)

## ESTRUTURA DO PROJETO:
[Incluir estrutura de diretórios conforme especificação]

## ALGORITMOS DE DETECÇÃO:
[Incluir algoritmos de detecção conforme especificação]

## INTERFACE:
Implemente interface responsiva, profissional, com tema escuro disponível.
Dashboard deve ser a página principal após análise.
Todas as tabelas devem ser paginadas e com busca.
Gráficos devem ser interativos.
Alertas devem ter destaque visual por severidade.

## ENTREGÁVEIS:
1. Código fonte completo e funcional
2. Arquivo requirements.txt
3. docker-compose.yml para deploy
4. Arquivo de migração do banco
5. README com instruções de instalação e uso
```

---

## 🚀 PARTE 5: Roadmap de Implementação

### Fase 1: Base (Semana 1-2)
- [ ] Setup do projeto Flask
- [ ] Modelos de banco de dados
- [ ] Sistema de upload de arquivos
- [ ] Parser básico de pcapng com Scapy
- [ ] Templates base

### Fase 2: Análise Core (Semana 3-4)
- [ ] Extração de IPs e estatísticas
- [ ] Análise de protocolos
- [ ] Detecção de port scan
- [ ] Detecção de ARP spoofing
- [ ] Dashboard básico

### Fase 3: Análises Avançadas (Semana 5-6)
- [ ] Análise DNS (tunneling, DGA)
- [ ] Análise TLS/SSL
- [ ] Detecção de beaconing
- [ ] Sistema de alertas completo

### Fase 4: Interface e Relatórios (Semana 7-8)
- [ ] Interface completa do dashboard
- [ ] Gerenciamento de IPs e ranges
- [ ] Visualizador de pacotes
- [ ] Geração de relatórios
- [ ] Tema escuro

### Fase 5: Integrações (Semana 9-10)
- [ ] Integração AbuseIPDB
- [ ] Integração IPsum
- [ ] Geolocalização
- [ ] Processamento em background com Celery

### Fase 6: Polimento (Semana 11-12)
- [ ] Testes automatizados
- [ ] Documentação
- [ ] Docker compose
- [ ] Otimização de performance
- [ ] Revisão de segurança

---

## 🎯 PARTE 6: Versão Simplificada (MVP)

Para uma primeira versão funcional mais rápida, considerar esta estrutura simplificada:

### 6.1 Arquitetura MVP (3 arquivos principais)

```
pcap-analyzer-mvp/
├── pcap_analyzer.py      # Motor de análise (Scapy)
├── pcap_server.py        # Servidor Flask + API REST
├── templates/
│   └── index.html        # Interface única com abas
├── static/
│   └── style.css         # Estilos customizados
├── data/
│   ├── settings.json     # IPs confiáveis + descrições
│   └── results.json      # Último resultado de análise
└── requirements.txt
```

### 6.2 Persistência Simplificada (JSON)

Em vez de banco de dados, usar arquivos JSON para persistência:

**settings.json:**
```json
{
  "trusted_ips": [
    {"ip": "192.168.1.0/24", "description": "Rede Local"},
    {"ip": "8.8.8.8", "description": "Google DNS"}
  ],
  "ip_descriptions": [
    {"ip": "192.168.1.1", "name": "Gateway/Router"},
    {"ip": "192.168.1.50", "name": "Servidor Web"}
  ],
  "thresholds": {
    "port_scan_min": 20,
    "arp_gratuitous_max": 5
  }
}
```

**results.json:**
```json
{
  "filename": "capture.pcapng",
  "analyzed_at": "2026-01-29T10:30:00",
  "summary": {...},
  "ips": [...],
  "protocols": [...],
  "alerts": [...]
}
```

### 6.3 Interface em Abas (Single Page)

Organização da interface em **5 abas** dentro de uma única página:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  [📊 Visão Geral] [🖥️ IPs e Tráfego] [📡 Protocolos] [⚠️ Alertas] [⚙️ Config] │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│                    [Conteúdo da aba selecionada]                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.4 API REST Simplificada

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/api/upload` | Upload PCAP (multipart/form-data) |
| GET | `/api/results` | Retorna última análise |
| GET | `/api/settings` | Carrega configurações |
| POST | `/api/settings` | Salva configurações |
| POST | `/api/trusted-ips` | Adiciona IP/range confiável |
| DELETE | `/api/trusted-ips/<ip>` | Remove IP confiável |
| POST | `/api/ip-descriptions` | Adiciona descrição de IP |
| DELETE | `/api/ip-descriptions/<ip>` | Remove descrição |
| GET | `/api/export` | Download JSON completo |
| POST | `/api/clear` | Limpa análise atual |

### 6.5 Processamento Assíncrono Simples

Para MVP, usar `threading` em vez de Celery:

```python
import threading

@app.route('/api/upload', methods=['POST'])
def upload_file():
    file = request.files['pcap']
    filepath = save_file(file)
    
    # Processar em background
    thread = threading.Thread(target=analyze_pcap, args=(filepath,))
    thread.start()
    
    return jsonify({'status': 'processing', 'message': 'Análise iniciada'})

@app.route('/api/results')
def get_results():
    if os.path.exists('data/results.json'):
        with open('data/results.json') as f:
            return jsonify(json.load(f))
    return jsonify({'status': 'no_data'})
```

### 6.6 Detalhes Visuais da Interface

#### Cards de Estatísticas (Visão Geral)
```
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ 📦 Pacotes   │ │ 📊 Dados     │ │ ⏱️ Duração   │
│   125,432    │ │   45.2 MB    │ │   00:45:23   │
└──────────────┘ └──────────────┘ └──────────────┘
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ 🌐 IPs       │ │ 📡 Protocolos│ │ ⚠️ Alertas   │
│     47       │ │     12       │ │   5 ⚠️ 2 🚨   │
└──────────────┘ └──────────────┘ └──────────────┘
```

#### Barra Visual de Tráfego (IPs e Tráfego)
```
┌─────────────────────────────────────────────────────────────────────┐
│ 192.168.1.105                                            [Gateway]  │
│ ├─ Enviados:   ████████████████████████░░░░░░░░░  8.2 MB (65%)     │
│ └─ Recebidos:  ██████████░░░░░░░░░░░░░░░░░░░░░░░  4.1 MB (35%)     │
│ Pacotes: 23,456 | Protocolos: TCP UDP DNS | Portas: 80, 443, 53    │
│ ⚠️ 3 alertas | [Descrever] [⭐ Confiável] [📋 Detalhes]             │
└─────────────────────────────────────────────────────────────────────┘
```

#### Badges de Risco (Protocolos)
```
┌─────────────────────────────────────────────────────────────────────┐
│ Protocolo  │ Pacotes │ Bytes   │ Risco │ Avisos                    │
├────────────┼─────────┼─────────┼───────┼───────────────────────────┤
│ HTTPS      │ 45,234  │ 89.2 MB │ 🟢    │ --                        │
│ DNS        │ 4,521   │ 1.2 MB  │ 🟢    │ --                        │
│ HTTP       │ 8,234   │ 12.1 MB │ 🟡    │ ⚠️ Sem criptografia        │
│ FTP        │ 89      │ 0.2 MB  │ 🔴    │ ⚠️ Senhas em texto plano   │
│ Telnet     │ 12      │ 0.01 MB │ 🔴    │ 🚨 Extremamente inseguro   │
└─────────────────────────────────────────────────────────────────────┘
```

### 6.7 Mensagens de Alerta Padronizadas

| Condição | Tipo | Mensagem |
|----------|------|----------|
| Porta 4444 detectada | ⚠️ warning | "Porta suspeita 4444 (Metasploit) detectada em {IP}" |
| Porta 31337 detectada | 🚨 danger | "Porta suspeita 31337 (Back Orifice) detectada em {IP}" |
| >20 portas por IP | 🚨 danger | "Possível port scan: {IP} acessou {N} portas diferentes" |
| HTTP na porta 80 | ⚠️ warning | "Tráfego HTTP não criptografado detectado" |
| FTP detectado | ⚠️ warning | "Protocolo FTP inseguro (senhas em texto plano)" |
| Telnet detectado | 🚨 danger | "Protocolo Telnet extremamente inseguro detectado" |
| >5 protocolos diferentes | ⚠️ warning | "Diversidade alta de protocolos ({N} diferentes)" |
| ARP anormal | 🚨 danger | "Possível ARP Spoofing detectado de {MAC}" |
| IP em blacklist | 🚨 danger | "IP {IP} encontrado em lista de ameaças conhecidas" |

---

## 📚 Referências e Recursos

### Bibliotecas Python
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [pyshark Documentation](https://github.com/KimiNewt/pyshark)
- [Flask Documentation](https://flask.palletsprojects.com/)

### Threat Intelligence
- [AbuseIPDB API](https://www.abuseipdb.com/api)
- [IPsum GitHub](https://github.com/stamparm/ipsum)
- [FireHOL IP Lists](https://iplists.firehol.org/)

### Padrões de Ataque
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Wireshark Wiki](https://wiki.wireshark.org/)

---

*Documento gerado em: 29/01/2026*
*Versão: 1.0*
