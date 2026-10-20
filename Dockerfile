FROM python:3.12.3-slim

WORKDIR /app

COPY requirements.txt requirements.lock ./
RUN python -m pip install --no-cache-dir --requirement requirements.lock

COPY pytest.ini ./
COPY src ./src
COPY tests ./tests

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Flask binds to all interfaces inside the isolated container so Docker can
# publish it on the host loopback interface. Use the documented loopback-only
# publish flag; the application still performs no collection or outbound I/O.
EXPOSE 8000

CMD ["python", "-m", "minisoc.app", "--host", "0.0.0.0", "--port", "8000"]
