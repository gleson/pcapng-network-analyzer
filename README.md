# PCAP Network Analyzer

Sistema web desenvolvido em Flask para análise profunda de arquivos `.pcap` e `.pcapng` do Wireshark, com foco em detecção de ameaças de segurança e análise de tráfego de rede.

## Funcionalidades

### Análises de Segurança

- **Port Scan Detection**: Detecta varreduras de portas (SYN scan, Connect scan)
- **Suspicious Ports**: Identifica portas maliciosas conhecidas (Metasploit, Back Orifice, etc.)
- **ARP Spoofing**: Detecta ARP poisoning e conflitos IP-MAC
- **DNS Tunneling**: Identifica possível exfiltração de dados via DNS
- **Insecure Protocols**: Alerta sobre uso de FTP, Telnet e outros protocolos inseguros

### Dashboard e Visualizações

- **Visão Geral**: Cards com métricas resumidas (pacotes, bytes, duração, IPs, protocolos, alertas)
- **Gráficos Interativos**:
  - Tráfego ao longo do tempo (Chart.js)
  - Distribuição de protocolos (gráfico de pizza)
- **Tabelas Dinâmicas**: IPs e protocolos com filtros e ordenação (DataTables)
- **Lista de Alertas**: Alertas categorizados por severidade (crítico, alto, médio, baixo)

### Gerenciamento

- **Configurações**: Ajuste de thresholds de detecção
- **Ranges Confiáveis**: Gerenciamento de IPs/ranges confiáveis
- **Classificação Automática**: IPs locais vs externos
- **Classificação de Risco**: Protocolos categorizados por nível de risco

## Requisitos

- **Python**: 3.11 ou superior
- **Sistema Operacional**: Linux, macOS ou Windows
- **Dependências**: Flask, Scapy, python-magic

## Instalação

### 1. Clonar o repositório (se aplicável)

```bash
cd /caminho/do/projeto/analisar_pcapng
```

### 2. Criar ambiente virtual (recomendado)

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows
```

### 3. Instalar dependências

```bash
pip install -r requirements.txt
```

### 4. Verificar estrutura de diretórios

Certifique-se de que os diretórios necessários existem:

```bash
mkdir -p data/uploads
```

## Como Usar

### 1. Iniciar o servidor

```bash
python app.py
```

O servidor iniciará em `http://localhost:5000`

### 2. Acessar a interface web

Abra seu navegador e acesse: `http://localhost:5000`

### 3. Fazer upload de arquivo PCAP

1. Clique no botão de seleção de arquivo
2. Escolha um arquivo `.pcap` ou `.pcapng` (máx. 500MB)
3. Clique em "Analyze"
4. Aguarde o processamento (a barra de progresso será exibida)

### 4. Visualizar resultados

Após a análise, os resultados serão exibidos em 5 abas:

#### Visão Geral
- Cards com métricas resumidas
- Gráfico de tráfego ao longo do tempo
- Gráfico de distribuição de protocolos
- Alertas recentes

#### IPs e Tráfego
- Lista completa de IPs detectados
- Classificação: Local vs Externo
- Estatísticas de pacotes e bytes (enviados/recebidos)
- Protocolos utilizados por IP
- Contador de alertas por IP

#### Protocolos
- Lista de protocolos detectados
- Estatísticas: pacotes, bytes, percentual
- Classificação de risco (baixo/médio/alto)
- Avisos de segurança por protocolo

#### Alertas
- Lista completa de alertas de segurança
- Filtros por severidade
- Detalhes técnicos e recomendações

#### Configurações
- Ajuste de thresholds de detecção
- Gerenciamento de ranges confiáveis
- Opção de limpar análise

## Estrutura de Arquivos

```
analisar_pcapng/
├── app.py                      # Servidor Flask e API REST
├── pcap_analyzer.py            # Motor de análise com Scapy
├── requirements.txt            # Dependências Python
├── README.md                   # Este arquivo
├── data/
│   ├── settings.json           # Configurações
│   ├── results.json            # Última análise (gerado)
│   └── uploads/                # Arquivos PCAP enviados
├── templates/
│   └── index.html              # Interface web
└── static/
    ├── css/
    │   └── style.css           # Estilos customizados
    └── js/
        └── app.js              # Lógica frontend
```

## Detecções Implementadas

### 1. Port Scan Detection

**Indicadores:**
- IP enviando SYN para múltiplas portas (>20 portas por padrão)
- Janela de tempo curta (<30 segundos)

**Severidade:** Crítica

**Recomendação:** Investigar atividade do host, possível comprometimento

### 2. Suspicious Ports

**Portas monitoradas:**
- 4444 - Metasploit Default
- 31337 - Back Orifice
- 666 - Doom Backdoor
- 6666 - IRC Backdoor
- 27374 - SubSeven Trojan
- E outras...

**Severidades:** Crítica, Alta, Média

**Recomendação:** Investigar tráfego, provável atividade maliciosa

### 3. ARP Spoofing

**Indicadores:**
- Gratuitous ARP excessivo (>5 por padrão)
- Conflitos IP-MAC (mesmo IP com MACs diferentes)

**Severidade:** Crítica

**Recomendação:** Verificar integridade da rede, possível man-in-the-middle

### 4. DNS Tunneling

**Indicadores:**
- Subdomínios muito longos (>50 caracteres)
- Alta entropia (>3.5) - caracteres aleatórios

**Severidade:** Crítica

**Recomendação:** Bloquear domínio, investigar malware no host

### 5. Insecure Protocols

**Protocolos alertados:**
- **FTP** (porta 21): Credenciais em texto plano
- **Telnet** (porta 23): Extremamente inseguro

**Severidades:** Alta/Crítica

**Recomendação:** Migrar para protocolos seguros (SFTP, SSH)

## Configurações

### Thresholds Padrão

```json
{
    "port_scan_min_ports": 20,
    "port_scan_time_window": 30,
    "arp_gratuitous_max": 5,
    "dns_subdomain_length": 50,
    "dns_entropy_min": 3.5
}
```

### Ranges Confiáveis Padrão

- `192.168.1.0/24` - Rede Local
- `10.0.0.0/8` - Rede Interna
- `172.16.0.0/12` - Rede Interna
- `8.8.8.0/24` - Google DNS
- `1.1.1.0/24` - Cloudflare DNS

## API REST

### Endpoints Disponíveis

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/` | Interface principal |
| POST | `/api/upload` | Upload de arquivo PCAP |
| GET | `/api/status` | Status da análise em andamento |
| GET | `/api/results` | Resultados da última análise |
| GET | `/api/settings` | Carregar configurações |
| POST | `/api/settings` | Salvar configurações |
| POST | `/api/ip-description` | Adicionar descrição de IP |
| POST | `/api/trusted-range` | Adicionar range confiável |
| DELETE | `/api/trusted-range/<cidr>` | Remover range confiável |
| POST | `/api/clear` | Limpar análise atual |

## Classificação de Risco de Protocolos

### Baixo Risco (Verde)
DNS, HTTPS, TLS, SSH, ICMP, NTP, DHCP

### Médio Risco (Amarelo)
TCP, UDP, HTTP, SMTP

### Alto Risco (Vermelho)
FTP, Telnet, ARP, SMBv1, SNMP

## Limitações Conhecidas

- Tamanho máximo de arquivo: 500MB
- Processamento síncrono (pode demorar para arquivos grandes)
- Sem histórico de múltiplas análises (apenas a última)
- Sem persistência em banco de dados (usa JSON)

## Melhorias Futuras

- [ ] Migração para PostgreSQL/SQLite
- [ ] Processamento com Celery + Redis
- [ ] Histórico de múltiplas análises
- [ ] Integração com Threat Intelligence APIs (AbuseIPDB, IPsum)
- [ ] Detecção de beaconing (C2 communication)
- [ ] Detecção de brute force (SSH, FTP)
- [ ] Visualizador de pacotes estilo Wireshark
- [ ] Geração de relatórios PDF/HTML
- [ ] Tema escuro
- [ ] Geolocalização de IPs externos

## Troubleshooting

### Erro ao carregar Scapy

```bash
# Linux: Instalar libpcap
sudo apt-get install libpcap-dev

# macOS: Instalar via Homebrew
brew install libpcap
```

### Permissões de arquivo

```bash
# Garantir que o diretório data/ tem permissões corretas
chmod 755 data/
chmod 755 data/uploads/
```

### Porta 5000 em uso

Edite `app.py` e altere a porta:

```python
app.run(debug=True, host='0.0.0.0', port=8080)
```

## Licença

Este projeto é fornecido "como está", sem garantias.

## Autor

Desenvolvido para análise de segurança de rede e detecção de ameaças.

## Contribuindo

Sugestões e melhorias são bem-vindas!

---

**Versão:** 1.0 (MVP)
**Data:** 2026-01-29
