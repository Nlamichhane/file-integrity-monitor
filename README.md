# File Integrity Monitor (FIM)

A lightweight, zero-dependency file integrity monitor you can run locally or in CI.
It builds a cryptographic **baseline** of files and later **scans** for changes (added/removed/modified).

## Features
- Baseline + scan + watch modes (polling)  
- SHA-256 by default (choose from hashlib-supported algorithms)
- Exclude patterns via glob (e.g. `__pycache__/*`, `*.log`)  
- JSON or human-readable output
- Logs to `logs/changes.log` and sensible exit codes (0=no changes, 2=changes, 1=error)
- Packaged CLI: `fim`

## Quick Start

```bash
# 1) (Optional) create & activate a venv
python3 -m venv .venv && source .venv/bin/activate

# 2) Install (editable)
pip install -e .

# 3) Initialize a baseline from example config
fim --config examples/config.json --baseline state/baseline.json baseline

# 4) Scan later to detect changes
fim scan --config examples/config.json --baseline state/baseline.json

# 5) Watch mode (polling every 15s by default)
fim watch --config examples/config.json --baseline state/baseline.json --interval 15
```

### Exit Codes
- `0` – No changes detected
- `2` – Changes found (added/removed/modified)
- `1` – Error

### JSON Output
```bash
fim scan --config examples/config.json --baseline state/baseline.json --json
```

### Config Schema (`examples/config.json`)
```json
{
  "paths": ["./"],
  "excludes": ["__pycache__/*", "*.pyc", ".git/*", "state/*", "logs/*", ".venv/*"],
  "algorithm": "sha256",
  "follow_symlinks": false,
  "ignore_hidden": true
}
```

### Security Tips
- Store your baseline in a protected location (ideally off the monitored host).  
- Commit the config, but **avoid** committing baselines containing sensitive paths.  
- Consider monitoring permissions using `--track-perms`.

## Development

Run tests:
```bash
python -m unittest
```

## License
[MIT](LICENSE)
