FROM python:3.14-slim

RUN apt update && apt dist-upgrade -y && apt install -y --no-install-recommends sshpass openssh-client && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt lws.py api.py /app/
COPY lws_core/ /app/lws_core/
COPY lws_commands/ /app/lws_commands/

WORKDIR /app

RUN pip install -r requirements.txt

RUN chmod +x lws.py

RUN useradd --create-home --shell /usr/sbin/nologin lws && \
    chown -R lws:lws /app
USER lws

CMD python3 api.py
