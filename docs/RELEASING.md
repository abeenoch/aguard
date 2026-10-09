# Releasing

## Resolved: the import name

The distribution is `a-guard`, and the import package is **`aguard`**:

```python
from aguard import ResourceServerGuard
```

An earlier revision shipped a top-level package literally named `app`. That is
a generic name which collides with any user's own `app` package, and
`pip install a-guard` would then silently shadow it. Renamed **before** the
first upload — a published import name cannot be withdrawn from anyone's
`pip freeze`.

## 0. Preconditions

- `pytest` is green.
- The wheel actually contains its data files. A missing `schema.sql` only
  surfaces *after* install, when `agctl init` fails:

```bash
python -m build --wheel --outdir dist
python -c "import zipfile,glob; z=zipfile.ZipFile(glob.glob('dist/*.whl')[0]); \
print([n for n in z.namelist() if n.endswith('.sql') or n.endswith('entry_points.txt')])"
# expect: ['aguard/db/schema.sql', 'a_guard-0.1.0.dist-info/entry_points.txt']
```

## 1. Build

```bash
rm -rf dist build          # never ship a stale artifact
python -m build
```

## 2. Validate the metadata

```bash
python -m twine check dist/*
```

## 3. Dry run on TestPyPI (do this once per project)

```bash
python -m twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ --no-deps a-guard
agctl --help               # the console script must exist
```

## 4. Publish

```bash
python -m twine upload dist/*
```

## 5. Tag and push

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

## Versioning

The version lives in **`pyproject.toml` only**. Bump it there, rebuild, tag to
match (`vX.Y.Z`). Nothing else in the tree should carry a version string.
