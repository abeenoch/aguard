FROM python:3.11-slim

WORKDIR /srv/a-guard

# Dependencies first — layer cache survives source edits
COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -e .

COPY app ./app
COPY scripts ./scripts

# Non-root: the app never needs root, and neither should its container
RUN useradd --create-home --uid 1000 guard
USER guard

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
