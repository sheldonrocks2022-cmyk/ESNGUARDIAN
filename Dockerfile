FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir .
COPY esn_guardian ./esn_guardian

ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "esn_guardian.main"]
