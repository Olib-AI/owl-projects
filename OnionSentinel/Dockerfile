FROM apify/actor-python:3.12

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./

ENV APIFY_LOCAL_STORAGE_DIR=/app/apify_storage
ENV APIFY_HEADLESS=1

RUN mkdir -p /app/apify_storage/datasets/default \
    /app/apify_storage/key_value_stores/default \
    /app/apify_storage/request_queues/default

CMD ["python", "main.py"]
