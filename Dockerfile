FROM python:3.11-slim

WORKDIR /srv/a-guard

# Source FIRST, then install. The tempting "dependencies first" ordering
# (COPY pyproject.toml, then `pip install -e .`) is broken for this project:
# with no aguard/ directory, [tool.setuptools.packages.find] matches nothing,
# setuptools builds a wheel containing only dist-info, and the install
# SUCCEEDS. The image then builds green and dies at the first `import aguard`.
# README.md and LICENSE come along because the package metadata names them.
COPY pyproject.toml README.md LICENSE ./
COPY aguard ./aguard
COPY scripts ./scripts

# Non-editable on purpose: an image should contain a built artifact, not a
# source tree plus a .pth that happens to point at it — so the installed
# package is verifiable with `docker exec ... python -c "import aguard"`.
RUN pip install --no-cache-dir .

# Non-root: the app never needs root, and neither should its container.
# The signing-key directory must be WRITABLE by that user, otherwise startup
# fails when the app tries to create data/keys/keys.json (WORKDIR is root-owned).
RUN useradd --create-home --uid 1000 guard \
 && mkdir -p /srv/a-guard/data/keys \
 && chown -R guard:guard /srv/a-guard
USER guard

EXPOSE 8000
CMD ["uvicorn", "aguard.main:app", "--host", "0.0.0.0", "--port", "8000"]
