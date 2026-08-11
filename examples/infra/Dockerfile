FROM python:3.12-slim

# Provision a TLS server key and an SSH deploy key at build time.
RUN openssl genrsa -out /etc/ssl/private/server.key 2048
RUN ssh-keygen -t ecdsa -f /root/.ssh/id_ecdsa -N ""

COPY app/ /app/
