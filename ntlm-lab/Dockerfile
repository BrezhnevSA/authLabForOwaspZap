FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py ntlm_users.txt ./
ENV NTLM_USER_FILE=/app/ntlm_users.txt
EXPOSE 8080
CMD ["python","server.py"]
