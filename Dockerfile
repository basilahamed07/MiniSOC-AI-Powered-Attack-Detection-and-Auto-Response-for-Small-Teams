FROM python:3.12.3-slim

WORKDIR /app

COPY requirements.txt requirements.lock ./
RUN python -m pip install --no-cache-dir --requirement requirements.lock

COPY pytest.ini ./
COPY src ./src
COPY tests ./tests

ENV PYTHONPATH=/app/src

CMD ["python", "-m", "minisoc.attack_simulator"]
