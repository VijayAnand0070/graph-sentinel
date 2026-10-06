FROM python:3.12-slim

RUN pip install --no-cache-dir "huggingface_hub[hf_xet]>=1.1,<2"
WORKDIR /app
COPY app.py /app/app.py

ENV PYTHONUNBUFFERED=1
EXPOSE 7860
CMD ["python", "/app/app.py"]

