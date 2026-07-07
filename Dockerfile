FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir requests==2.32.3
COPY *.py .
EXPOSE 8080
USER 65532:65532
CMD ["python", "handler.py"]
