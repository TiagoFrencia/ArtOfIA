FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies if nuclei/nmap were to run locally, 
# but here we use Docker remote execution, so we only need python deps.
# However, we need 'docker' and 'mcp' libraries.

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt docker

COPY app ./app

EXPOSE 8000

CMD ["python", "-m", "app.main"]
