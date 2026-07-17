# Contributing

Keep contributions passive, reproducible, and source-linked.

1. Add or update an offline test for every change.
2. Record the source URL and the exact claim supported by it.
3. Keep network collectors on the explicit allowlist.
4. Defang network indicators in Markdown; retain raw values only in machine output.
5. Label inference as inference. A DNS answer or shared cloud address is not actor
   attribution.

Install the hash-locked audit environment, then run every gate before opening a pull request:

```powershell
python -m pip install --require-hashes -r requirements-build.lock
python -m pip install --require-hashes -r requirements-ci.lock
python -m pip install --no-build-isolation --no-deps -e .
ruff check .
bandit -r src -q
pip-audit --require-hashes -r requirements-ci.lock --progress-spinner off
zizmor --persona auditor .
pytest
```
