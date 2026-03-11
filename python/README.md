# erc8128 (Python)

Python implementation of ERC-8128 signing and verification.

## HTTP transport

The built-in transport uses `httpx` in `default_fetch`.

If you want to integrate with another HTTP client, pass a custom `fetch` callable via `ClientOptions`.

## Development

```bash
uv sync
uv run python -m unittest discover -s tests -v
```
