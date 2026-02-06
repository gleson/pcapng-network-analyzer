#!/bin/bash
set -e

echo "Aguardando PostgreSQL..."

# Aguardar PostgreSQL estar pronto (backup do healthcheck)
until python -c "
import psycopg2
import os
try:
    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    conn.close()
    print('PostgreSQL disponivel')
except Exception as e:
    print(f'Aguardando... {e}')
    exit(1)
" 2>/dev/null; do
    sleep 1
done

echo "Iniciando PCAP Network Analyzer..."
exec python app.py
