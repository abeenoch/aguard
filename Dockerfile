FROM python:3.11-slim

WORKDIR /srv/a-guard

# Dependencies first — layer cache survives source edits
COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -e .

COPY app ./app
COPY scripts ./scripts

# Non-root: the app never needs root, and neither should its container.
# The signing-key directory must be WRITABLE by that user, otherwise startup
# fails when the app tries to create data/keys/keys.json (WORKDIR is root-owned).
RUN useradd --create-home --uid 1000 guard \
 && mkdir -p /srv/a-guard/data/keys \
 && chown -R guard:guard /srv/a-guard
USER guard

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
