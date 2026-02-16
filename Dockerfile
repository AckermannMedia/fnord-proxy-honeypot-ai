FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY fnord.conf.example ./fnord.conf.example
COPY landing/ ./landing/

EXPOSE 8888

CMD ["python3", "app.py"]
