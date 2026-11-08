# API simulada del SOC (código ORIGINAL de la organización, sin modificar: solo se copia a la imagen).
# Los datos del reto se montan en solo lectura desde docker-compose.yml; 06_herramientas es un volumen con nombre
# para que el registro de contención (containment_log.jsonl) persista sin escribir en DTT-UAB-The-Hack-main.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY DTT-UAB-The-Hack-main/06_herramientas/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY DTT-UAB-The-Hack-main/06_herramientas/mock_soc_api.py /dataset/06_herramientas/mock_soc_api.py
RUN useradd --uid 10001 --no-create-home soc && chown -R soc /dataset/06_herramientas
USER soc
WORKDIR /dataset/06_herramientas

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=6 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/alerts?limit=1', timeout=4)"
CMD ["uvicorn", "mock_soc_api:app", "--host", "0.0.0.0", "--port", "8000"]
