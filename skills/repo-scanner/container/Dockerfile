# repo-scanner isolated scanner image.
#
# Why: the default audit runs git + python on the host. Hooks are disabled and
# nothing from the repo is executed, but parser-level exploits (git, file
# readers) remain a theoretical vector. This image gives full isolation:
# the clone and every scan phase run inside a throwaway container with the
# network dropped after fetch.
#
# Build (one-time, ~2GB due to torch) — run from the SKILL ROOT, because the
# build context must include scripts/ and requirements.txt (NOT from container/):
#   docker build -t repo-scanner-scanner -f container/Dockerfile .
#
# Run an isolated scan (network only for the clone stage):
#   docker run --rm -e REPO_URL=https://github.com/owner/repo \
#     -v repo-scanner-hf-cache:/root/.cache/huggingface \
#     repo-scanner-scanner
#
# The container prints promptguard JSON to stdout; the host-side orchestrator
# (Claude) feeds it to scorer.py as usual. Model weights persist in the named
# volume so they download once.

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /audit

COPY requirements.txt .
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r requirements.txt

COPY scripts/ scripts/

# Safe-clone then scan. Hooks disabled belt-and-suspenders even though the
# container is throwaway.
COPY container/scan-entrypoint.sh /usr/local/bin/scan-entrypoint.sh
RUN chmod +x /usr/local/bin/scan-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/scan-entrypoint.sh"]
