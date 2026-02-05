# Guia Rápido de Início

## Instalação Rápida

```bash
# 1. Instalar dependências
pip3 install -r requirements.txt

# 2. Iniciar servidor
python3 app.py
```

O servidor iniciará em: `http://localhost:5000`

## Obtendo Arquivos PCAP para Teste

### Opção 1: Capturar tráfego com Wireshark

1. Instale o Wireshark: `sudo apt install wireshark` (Linux) ou baixe de https://www.wireshark.org
2. Inicie a captura em uma interface de rede
3. Deixe capturar por alguns minutos
4. Salve como `.pcapng`

### Opção 2: Usar Datasets Públicos

**Malware Traffic Analysis** (RECOMENDADO)
- URL: https://www.malware-traffic-analysis.net/
- Diversos arquivos PCAP com tráfego malicioso real
- Excelente para testar detecções de segurança

**Wireshark Sample Captures**
- URL: https://wiki.wireshark.org/SampleCaptures
- Exemplos de diversos protocolos
- Bom para testar análise de protocolos

**PacketLife.net**
- URL: https://packetlife.net/captures/
- Capturas categorizadas por tipo

### Opção 3: Gerar Tráfego Sintético com Scapy

```python
from scapy.all import *

# Criar pacotes de teste
packets = []

# Tráfego HTTP normal
packets.append(IP(dst="8.8.8.8")/TCP(dport=80)/Raw(load="GET / HTTP/1.1"))

# Port scan simulado (gera alerta!)
for port in range(20, 100):
    packets.append(IP(dst="192.168.1.1")/TCP(dport=port, flags="S"))

# Salvar
wrpcap("test_capture.pcap", packets)
```

## Teste Básico do Sistema

### 1. Iniciar o servidor

```bash
python3 app.py
```

Você verá:
```
==================================================
PCAP Network Analyzer - Starting...
==================================================
Server running at: http://localhost:5000
Upload a .pcap or .pcapng file to begin analysis
==================================================
```

### 2. Acessar a interface

Abra o navegador em: `http://localhost:5000`

### 3. Upload de arquivo

1. Clique em "Escolher arquivo"
2. Selecione um arquivo `.pcap` ou `.pcapng`
3. Clique em "Analyze"
4. Aguarde o processamento

### 4. Verificar resultados

Após a análise, navegue pelas 5 abas:

**Visão Geral:**
- Verifique se os cards de métricas estão preenchidos
- Observe os gráficos de tráfego e protocolos
- Veja alertas recentes (se houver)

**IPs e Tráfego:**
- Tabela deve listar todos os IPs
- Classificação Local/Externo deve estar correta
- Estatísticas de tráfego devem aparecer

**Protocolos:**
- Lista de protocolos detectados
- Badges de risco (verde/amarelo/vermelho)
- Avisos de segurança (se aplicável)

**Alertas:**
- Se houver tráfego suspeito, alertas aparecerão aqui
- Teste os filtros por severidade
- Leia recomendações de segurança

**Configurações:**
- Ajuste thresholds
- Adicione ranges confiáveis
- Teste o botão "Limpar Análise"

## Testando Detecções Específicas

### Port Scan

Baixe qualquer PCAP de scan do nmap de:
https://www.malware-traffic-analysis.net/

Ou use: https://wiki.wireshark.org/SampleCaptures#Port_scan

**Esperado:** Alerta crítico de "Port Scan Detected"

### Portas Suspeitas

Procure PCAPs com backdoors/trojans em:
https://www.malware-traffic-analysis.net/

**Esperado:** Alertas para portas como 4444, 31337, etc.

### DNS Tunneling

Baixe PCAPs de DNS tunneling em:
https://www.malware-traffic-analysis.net/training-exercises.html

**Esperado:** Alerta crítico de "DNS Tunneling Suspected"

### Protocolos Inseguros

Qualquer PCAP com tráfego FTP ou Telnet.

Exemplo: https://wiki.wireshark.org/SampleCaptures#FTP

**Esperado:** Alerta alto de "Insecure Protocol"

## Troubleshooting

### Erro ao iniciar servidor

```bash
# Verifique se a porta 5000 está em uso
sudo netstat -tlnp | grep 5000

# Use outra porta se necessário
# Edite app.py, última linha:
app.run(debug=True, host='0.0.0.0', port=8080)
```

### Erro ao carregar arquivo grande

```bash
# Aumente o limite em app.py:
app.config['MAX_CONTENT_LENGTH'] = 1000 * 1024 * 1024  # 1GB
```

### Análise muito lenta

Para arquivos muito grandes (>100MB), o processamento pode demorar vários minutos. Monitore o terminal para ver o progresso.

## Validação de Funcionalidades

Checklist de teste:

- [ ] Upload de arquivo funciona
- [ ] Barra de progresso aparece durante análise
- [ ] Cards de métricas são preenchidos
- [ ] Gráfico de tráfego é renderizado
- [ ] Gráfico de protocolos é renderizado
- [ ] Tabela de IPs é populada e ordenável
- [ ] Tabela de protocolos é populada
- [ ] Alertas aparecem (se houver tráfego suspeito)
- [ ] Filtros de alertas funcionam
- [ ] Thresholds podem ser salvos
- [ ] Ranges confiáveis podem ser adicionados/removidos
- [ ] Botão "Limpar Análise" funciona

## Próximos Passos

1. **Teste com diferentes tipos de tráfego**
   - Tráfego normal vs malicioso
   - Diferentes protocolos
   - Diferentes tamanhos de arquivo

2. **Ajuste thresholds**
   - Configure para seu ambiente
   - Reduza falsos positivos

3. **Configure ranges confiáveis**
   - Adicione suas redes internas
   - Adicione servidores conhecidos

4. **Explore detecções**
   - Entenda cada tipo de alerta
   - Siga as recomendações de segurança

## Suporte

Para problemas ou dúvidas:
- Verifique o README.md
- Revise a especificação completa em pcapng_analyzer_specification.md
- Confira logs no terminal onde o servidor está rodando

---

**Versão:** 1.0 (MVP)
**Data:** 2026-01-29
