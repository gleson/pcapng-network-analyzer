# PCAP Network Analyzer

Sistema web desenvolvido em Flask para análise profunda de arquivos `.pcap` e `.pcapng` do Wireshark, com foco em detecção de ameaças de segurança e análise de tráfego de rede. Utiliza PostgreSQL para persistência e Docker para orquestração.

## Funcionalidades

### Análises de Segurança

- **Port Scan Detection**: Detecta varreduras de portas (SYN scan, Connect scan)
- **Suspicious Ports**: Identifica portas maliciosas conhecidas (Metasploit, Back Orifice, SubSeven, etc.)
- **ARP Spoofing**: Detecta ARP poisoning, flood e conflitos IP-MAC
- **DNS Tunneling**: Identifica possível exfiltração de dados via DNS (entropia e comprimento de subdomínios)
- **Insecure Protocols**: Alerta sobre uso de FTP, Telnet e outros protocolos inseguros
- **IP-MAC Changes**: Detecta múltiplos endereços MAC associados ao mesmo IP
- **External SMB Access**: Monitora tráfego SMB de/para redes externas (portas 445, 139)

### Dashboard e Visualizações

- **Visão Geral**: Cards com métricas resumidas (pacotes, bytes, duração, IPs, protocolos, alertas)
- **Gráficos Interativos**:
  - Tráfego ao longo do tempo (Chart.js)
  - Distribuição de protocolos (gráfico de pizza)
- **Tabelas Dinâmicas**: IPs e protocolos com filtros e ordenação (DataTables)
- **Lista de Alertas**: Alertas categorizados por severidade (crítico, alto, médio, baixo)
- **Estatísticas por Protocolo**: Clique em um protocolo para ver detalhamento por IP

### Histórico e Visualização Agregada

- **Histórico de Scans**: Todos os scans realizados são armazenados em PostgreSQL
- **Visualização Individual**: Ver resultados de um scan específico
- **Visualização Agregada**: Combinar múltiplos scans selecionados ou todos os scans em uma visão unificada
- **Seleção de Scans**: Checkboxes para selecionar quais scans agregar

### Filtro por Período

- **Data Inicial e Final**: Campos de data para filtrar o histórico de scans por período
- **Filtro na Agregação**: A visualização agregada respeita o filtro de período aplicado
- **Caso de Uso**: Verificar movimentações de rede entre duas datas específicas para auditoria

### Gerenciamento de IPs

- **Nomes de IPs**: Atribuir nomes personalizados a endereços IP (ex: "Servidor Web", "Router Principal")
- **Descrições**: Adicionar descrições para identificação facilitada
- **Evolução de IPs**: Visualizar a evolução de um IP ao longo de múltiplos scans (pacotes, bytes, alertas)
- **Classificação Automática**: IPs locais vs externos

### Geolocalização de IPs

- **Localização Automática**: IPs externos são geolocalizados automaticamente via ip-api.com
- **Cache Inteligente**: Resultados são cacheados no banco por 7 dias para evitar chamadas repetidas
- **Exibição**: País e cidade exibidos na tabela de IPs com bandeira emoji do país
- **Tooltip Detalhado**: Passe o mouse para ver região, país e ISP

### Exclusão de Análises

- **Exclusão Individual**: Remover um scan específico do histórico (botão de lixeira na tabela)
- **Exclusão em Lote**: Selecionar múltiplos scans e excluí-los de uma vez
- **Remoção Completa**: Ao excluir, os dados do banco de dados E o arquivo PCAP enviado são removidos permanentemente do disco
- **Caso de Uso - Auditoria**: Permite analisar arquivos PCAP com problemas de segurança conhecidos para fins de auditoria do sistema e, após a verificação, excluí-los completamente, já que não representam tráfego real da rede

### Dark Mode

- **Toggle no Navbar**: Botão para alternar entre tema claro e escuro
- **Persistência**: A preferência de tema é salva no localStorage do navegador
- **Adaptação Completa**: Todos os componentes (cards, tabelas, modais, gráficos, formulários) se adaptam ao tema

### Configurações

- **Thresholds de Detecção**: Ajuste dinâmico dos limites de detecção
- **Ranges Confiáveis**: Gerenciamento de IPs/ranges confiáveis (notação CIDR)
- **Classificação de Risco**: Protocolos categorizados por nível de risco
- **Limpar Análise**: Opção de limpar cache de análise

## Requisitos

- **Docker** e **Docker Compose** (recomendado)
- Ou: **Python 3.11+** e **PostgreSQL 15+** (instalação manual)

## Instalação com Docker (Recomendado)

### 1. Clonar o repositório

```bash
cd /caminho/do/projeto/analisar_pcapng
```

### 2. Subir os containers

```bash
docker compose up --build -d
```

Isso iniciará:
- **web**: Aplicação Flask na porta 5000
- **db**: PostgreSQL 15 com banco `pcap_analyzer`

### 3. Acessar a interface web

Abra seu navegador e acesse: `http://localhost:5000`

### 4. Parar os containers

```bash
docker compose down
```

Para remover também os volumes de dados:

```bash
docker compose down -v
```

## Instalação Manual (Sem Docker)

### 1. Criar ambiente virtual

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
```

### 2. Instalar dependências

```bash
pip install -r requirements.txt
```

### 3. Configurar PostgreSQL

Criar banco e usuário:

```sql
CREATE USER pcap_user WITH PASSWORD 'pcap_pass';
CREATE DATABASE pcap_analyzer OWNER pcap_user;
```

### 4. Configurar variável de ambiente

```bash
export DATABASE_URL=postgresql://pcap_user:pcap_pass@localhost:5432/pcap_analyzer
```

### 5. Iniciar o servidor

```bash
python app.py
```

## Variáveis de Ambiente

| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `DATABASE_URL` | URL de conexão PostgreSQL | `postgresql://pcap_user:pcap_pass@localhost:5432/pcap_analyzer` |
| `UPLOAD_FOLDER` | Diretório para arquivos PCAP | `data/uploads` |
| `SETTINGS_FILE` | Arquivo de configurações JSON | `data/settings.json` |

## Como Usar

### 1. Fazer upload de arquivo PCAP

1. Clique no botão de seleção de arquivo
2. Escolha um arquivo `.pcap` ou `.pcapng` (máx. 500MB)
3. Clique em "Analyze"
4. Aguarde o processamento (barra de progresso + geolocalização de IPs)

### 2. Visualizar resultados

Após a análise, os resultados são exibidos em 5 abas:

- **Visão Geral**: Métricas, gráficos de tráfego e protocolos, alertas recentes
- **IPs e Tráfego**: Tabela completa com nome, grupo, tipo, localização, estatísticas
- **Protocolos**: Estatísticas por protocolo com detalhamento de IPs
- **Alertas**: Filtros por severidade com detalhes e recomendações
- **Configurações**: Thresholds, ranges confiáveis, limpeza

### 3. Filtrar por período

1. Na seção "Histórico de Scans", preencha "Data Inicial" e/ou "Data Final"
2. Clique "Filtrar" para ver apenas scans no período
3. "Ver Todos (Agregado)" respeita o filtro aplicado
4. Clique "Limpar" para remover o filtro

### 4. Gerenciar histórico de scans

- **Ver individual**: Clique no ícone de olho
- **Ver agregado**: Selecione scans e clique "Ver Selecionados" ou "Ver Todos"
- **Excluir individual**: Clique no ícone de lixeira
- **Excluir em lote**: Selecione múltiplos scans e clique "Excluir Selecionados"

### 5. Alternar Dark Mode

Clique no ícone de lua/sol no canto superior direito do navbar.

### 6. Caso de uso: Auditoria de segurança

1. Faça upload de arquivos PCAP com tráfego de teste contendo problemas de segurança conhecidos
2. Analise os resultados para verificar se o sistema detecta corretamente as ameaças
3. Após a auditoria, selecione os scans de teste e exclua-os em lote
4. Os dados e arquivos são removidos permanentemente, mantendo o histórico limpo

## Estrutura de Arquivos

```
analisar_pcapng/
├── Dockerfile                  # Imagem Docker da aplicação
├── docker-compose.yml          # Orquestração Flask + PostgreSQL
├── docker-entrypoint.sh        # Script de inicialização do container
├── .dockerignore               # Arquivos ignorados no build Docker
├── app.py                      # Servidor Flask e API REST
├── pcap_analyzer.py            # Motor de análise com Scapy
├── database.py                 # Gerenciamento do banco PostgreSQL
├── requirements.txt            # Dependências Python
├── README.md                   # Este arquivo
├── data/
│   ├── settings.json           # Configurações
│   └── uploads/                # Arquivos PCAP enviados
├── templates/
│   └── index.html              # Interface web (SPA)
└── static/
    ├── css/
    │   └── style.css           # Estilos (light + dark mode)
    └── js/
        └── app.js              # Lógica frontend
```

## Detecções Implementadas

### 1. Port Scan Detection
- **Indicadores**: IP enviando SYN para >20 portas em <30 segundos
- **Severidade**: Crítica

### 2. Suspicious Ports
- **Portas**: 4444 (Metasploit), 31337 (Back Orifice), 666 (Doom), 6666 (IRC), 27374 (SubSeven), 5555 (ADB), 9001 (Tor), 1080 (SOCKS)
- **Severidades**: Crítica, Alta, Média

### 3. ARP Spoofing
- **Indicadores**: Gratuitous ARP excessivo (>5), conflitos IP-MAC
- **Severidade**: Crítica (spoofing) / Alta (flood)

### 4. DNS Tunneling
- **Indicadores**: Subdomínios >50 chars, entropia >3.5
- **Severidade**: Crítica

### 5. Insecure Protocols
- **FTP** (porta 21): Alta | **Telnet** (porta 23): Crítica

### 6. IP-MAC Changes
- **Severidade**: Alta (locais) / Média (externos)

### 7. External SMB Access
- **Severidade**: Crítica (inbound) / Alta (outbound)

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
| POST | `/api/upload` | Upload de arquivo PCAP/PCAPNG |
| GET | `/api/status` | Status da análise em andamento |
| GET | `/api/results` | Resultados (suporta `scan_id`, `view=aggregate`, `scan_ids`, `date_from`, `date_to`) |
| GET | `/api/scans` | Listar histórico (suporta `date_from`, `date_to`) |
| DELETE | `/api/scans/<id>` | Excluir um scan (dados + arquivo PCAP) |
| DELETE | `/api/scans/batch` | Excluir múltiplos scans em lote |
| GET | `/api/settings` | Carregar configurações |
| POST | `/api/settings` | Salvar configurações |
| GET | `/api/ip-names` | Listar todos os nomes de IPs |
| POST | `/api/ip-names` | Definir nome para um IP |
| DELETE | `/api/ip-names/<ip>` | Remover nome de um IP |
| POST | `/api/ip-description` | Adicionar descrição de IP (legado) |
| GET | `/api/ip-evolution/<ip>` | Evolução de um IP entre scans |
| POST | `/api/trusted-range` | Adicionar range confiável |
| DELETE | `/api/trusted-range/<cidr>` | Remover range confiável |
| POST | `/api/clear` | Limpar cache de análise |

## Classificação de Risco de Protocolos

| Nível | Protocolos |
|-------|-----------|
| Baixo (Verde) | DNS, HTTPS, TLS, SSH, ICMP, NTP, DHCP |
| Médio (Amarelo) | TCP, UDP, HTTP, SMTP, IPv6 |
| Alto (Vermelho) | FTP, Telnet, ARP, SMB, SMBv1, SNMP |

## Banco de Dados

O sistema utiliza **PostgreSQL 15** para persistência de dados com as seguintes tabelas:

- **scans**: Histórico de análises (metadados + resultados JSON completos)
- **ip_names**: Nomes personalizados para endereços IP
- **ip_stats**: Estatísticas de tráfego por IP por scan
- **alerts**: Alertas de segurança detectados por scan
- **protocol_stats**: Estatísticas de protocolos por scan
- **protocol_ip_stats**: Estatísticas de protocolos por IP por scan
- **ip_geolocation**: Cache de geolocalização de IPs externos (TTL: 7 dias)

Todas as tabelas relacionadas usam `ON DELETE CASCADE` para integridade referencial.

## Limitações Conhecidas

- Tamanho máximo de arquivo: 500MB
- Processamento síncrono (pode demorar para arquivos grandes)
- Geolocalização limitada a 45 requisições/minuto (API gratuita ip-api.com)
- Instância única do servidor (sem clustering)

## Melhorias Futuras

- [ ] Processamento assíncrono com Celery + Redis
- [ ] Integração com Threat Intelligence APIs (AbuseIPDB, IPsum)
- [ ] Detecção de beaconing (C2 communication)
- [ ] Detecção de brute force (SSH, FTP)
- [ ] Visualizador de pacotes estilo Wireshark
- [ ] Geração de relatórios PDF/HTML

## Troubleshooting

### Erro de conexão com PostgreSQL

Verifique se o container do banco está rodando:

```bash
docker compose ps
docker compose logs db
```

### Erro ao carregar Scapy (instalação manual)

```bash
# Linux: Instalar libpcap
sudo apt-get install libpcap-dev

# macOS: Instalar via Homebrew
brew install libpcap
```

### Porta 5000 em uso

Edite `docker-compose.yml` e altere o mapeamento de portas:

```yaml
ports:
  - "8080:5000"
```

### Resetar banco de dados

```bash
docker compose down -v
docker compose up --build -d
```

## Licença

Este projeto é fornecido "como está", sem garantias.

## Autor

Desenvolvido para análise de segurança de rede e detecção de ameaças.

## Contribuindo

Sugestões e melhorias são bem-vindas!

---

**Versão:** 2.0
**Data:** 2026-02-06
