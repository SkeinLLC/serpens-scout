# Contributing

Keep contributions passive, reproducible, and source-linked.

1. Add or update an offline test for every change.
2. Record the source URL and the exact claim supported by it.
3. Keep network collectors on the explicit allowlist.
4. Defang network indicators in Markdown; retain raw values only in machine output.
5. Label inference as inference. A DNS answer or shared cloud address is not actor
   attribution.

Run `pytest` and `ruff check .` before opening a pull request.
