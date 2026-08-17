FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends krb5-user curl && rm -rf /var/lib/apt/lists/*
COPY client-check.sh /client-check.sh
ENV KRB5_CONFIG=/shared/krb5.conf
CMD ["/client-check.sh"]
