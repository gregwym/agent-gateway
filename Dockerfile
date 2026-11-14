FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Exact, hash-checked versions: the ones the test suite ran against.
COPY requirements.txt ./
RUN pip install --require-hashes --only-binary=:all: -r requirements.txt \
 && useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin agw

# The package is run from source (`python -m agent_gateway`); nothing is built in the image.
COPY agent_gateway ./agent_gateway
COPY examples ./examples

USER 10001:10001
ENV AGW_CONFIG=/config/gateway.yaml
EXPOSE 8080

# Inside the container the gateway listens on every interface of its own network
# namespace; which host address reaches it is decided by `ports:` in the compose file.
ENTRYPOINT ["python", "-m", "agent_gateway"]
CMD ["serve", "--host", "0.0.0.0"]
