FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY brain/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt langgraph networkx pydantic hvac temporalio litellm opentelemetry-api

COPY brain/app ./app
COPY *.py ./

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
