FROM python:3.11-slim

# Dependencias do sistema para Scapy e python-magic
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    libmagic1 \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data/uploads

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/docker-entrypoint.sh"]
