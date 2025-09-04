FROM python:3.11-slim

RUN apt update && apt dist-upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt lws.py api.py /app/

WORKDIR /app

RUN pip install -r requirements.txt

RUN chmod +x lws.py && \

CMD python3 api.py
