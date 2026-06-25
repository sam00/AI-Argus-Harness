# AI-Argus-Harness — minimal, dependency-light image.
# The core harness has no hard third-party dependencies, so this stays small.
FROM python:3.12-slim

# Don't write .pyc files; flush logs immediately.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install the package (with the optional YAML extra for project config files).
COPY . /app
RUN pip install --no-cache-dir ".[yaml]"

# Run as a non-root user.
RUN useradd --create-home --uid 10001 argus
USER argus

# Reports are written under the working directory (mount a volume to persist).
ENTRYPOINT ["argus"]
CMD ["--help"]
