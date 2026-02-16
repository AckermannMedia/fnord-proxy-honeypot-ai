FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY app.py .
COPY fnord.conf.example ./fnord.conf.example

EXPOSE 8888

CMD ["python3", "app.py"]
