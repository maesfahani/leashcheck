# Build from the repository root:  docker build -t leash-claude -f leash/Dockerfile .
FROM node:22-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl git iptables less procps python3 ripgrep \
 && rm -rf /var/lib/apt/lists/* \
 && userdel -r node

RUN npm install -g @anthropic-ai/claude-code && npm cache clean --force

COPY leash/entrypoint.sh /usr/local/bin/leash-entrypoint
COPY leashcheck.py /opt/leashcheck.py
RUN chmod 755 /usr/local/bin/leash-entrypoint && mkdir -p /home/agent

ENV HOME=/home/agent DISABLE_AUTOUPDATER=1
ENTRYPOINT ["/usr/local/bin/leash-entrypoint"]
