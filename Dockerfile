FROM python:3.11-slim

WORKDIR /app

RUN useradd -m -u 1000 sentineluser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py vercel.json hsts.txt ./
COPY api ./api
COPY public ./public
COPY index.html exhaust.html sp-embed-preview.html ./

USER sentineluser

ENV PORT=8080
EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "8", "--timeout", "0", "server:app"]

