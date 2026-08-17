FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-gssapi krb5-user && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY server.py ./
ENV KRB5_CONFIG=/shared/krb5.conf KRB5_KTNAME=/shared/http.keytab
EXPOSE 8080
CMD ["python3","server.py"]
