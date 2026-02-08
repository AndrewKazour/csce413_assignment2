FROM python:3.11-slim

WORKDIR /app

COPY . .

# Create logs directory
RUN mkdir -p /app/logs

EXPOSE 8080
CMD ["python", "-u", "honeypot.py"]
