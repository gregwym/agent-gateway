FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Exact, hash-checked versions: the ones the test suite ran against.
COPY requirements.txt ./
RUN pip install --require-hashes --only-binary=:all: -r requirements.txt \
 && useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin agw \
 && install -d -o agw -g agw -m 0700 /browser

FROM base AS login-browser
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium fonts-noto-cjk \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --only-binary=:all: 'playwright==1.65.2' 'greenlet==3.5.6'
COPY agent_gateway ./agent_gateway
USER 10001:10001
ENV AGW_CHROMIUM=/usr/bin/chromium HOME=/tmp
ENTRYPOINT ["python", "-m", "agent_gateway.browser_worker"]
CMD ["/browser/control.sock"]

FROM base AS gateway
# Run directly from the source tree.
COPY agent_gateway ./agent_gateway
COPY examples ./examples
USER 10001:10001
ENV AGW_CONFIG=/config/gateway.yaml
EXPOSE 8080

# Inside the container the gateway listens on every interface of its own network
# namespace; which host address reaches it is decided by `ports:` in the compose file.
ENTRYPOINT ["python", "-m", "agent_gateway"]
CMD ["serve", "--host", "0.0.0.0"]
