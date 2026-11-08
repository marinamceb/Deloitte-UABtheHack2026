# Backend: agente de triaje (CLI agent.py) y consola web (FastAPI, servidor/). El dataset y salidas/ se montan.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    DATASET_DIR=/dataset SALIDAS_DIR=/datos/salidas FRONTEND_DIR=/sin-frontend \
    SOC_API_URL=http://host.docker.internal:8000 \
    PYTEST_ADDOPTS="-p no:cacheprovider"
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Usuario sin privilegios (docker-compose.yml lo sustituye por el UID del anfitrión para poder escribir en salidas/)
RUN useradd --uid 10001 --no-create-home agente
USER agente

EXPOSE 8001
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/api/salud', timeout=4)"
# --proxy-headers: la IP real del navegador (para la auditoría de accesos) llega desde nginx
CMD ["uvicorn", "servidor.app:app", "--host", "0.0.0.0", "--port", "8001", "--proxy-headers", "--forwarded-allow-ips", "*"]
