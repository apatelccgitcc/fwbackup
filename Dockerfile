FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 DATA_DIR=/data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
VOLUME ["/data"]
EXPOSE 8080
# one worker only: the nightly scheduler runs inside the app process
CMD ["uvicorn", "app.web:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--proxy-headers"]
