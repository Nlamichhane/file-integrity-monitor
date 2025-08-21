"""
Command-line interface for the File Integrity Monitor.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .monitor import (
    build_baseline,
    load_config,
    save_json,
    load_json,
    diff_states,
    configure_logging,
)


def _parse_args(argv):
    p = argparse.ArgumentParser(prog="fim", description="File Integrity Monitor (baseline, scan, watch)")
    p.add_argument("--config", "-c", type=str, required=True, help="Path to config.json")
    p.add_argument("--baseline", "-b", type=str, required=True, help="Path to baseline state JSON")
    p.add_argument("--log-file", type=str, default="logs/changes.log", help="Path to log file")
    p.add_argument("--json", action="store_true", help="Emit JSON output instead of human-readable")
    p.add_argument("--strict-mtime", action="store_true", help="Treat mtime drift as a change even when hash matches")
    p.add_argument("--track-perms", action="store_true", help="Track and compare UNIX permission bits (mode)")

    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("baseline", help="Build/overwrite baseline with current file state")

    scan = sub.add_parser("scan", help="Scan and compare against baseline once")
    # no extra flags

    watch = sub.add_parser("watch", help="Continuously scan on an interval")
    watch.add_argument("--interval", type=int, default=15, help="Polling interval seconds (default: 15)")

    return p.parse_args(argv)


def _state_from_config(cfg, track_perms=False):
    paths = [Path(p) for p in cfg["paths"]]
    excludes = cfg.get("excludes", [])
    algorithm = cfg.get("algorithm", "sha256")
    follow_symlinks = cfg.get("follow_symlinks", False)
    ignore_hidden = cfg.get("ignore_hidden", True)

    state = build_baseline(paths, excludes, algorithm, follow_symlinks, ignore_hidden, track_perms=track_perms)
    return state


def _print_or_json(result, as_json=False):
    if as_json:
        print(json.dumps(result, indent=2))
        return

    def _section(name, items):
        print(f"\n{name} ({len(items)}):")
        for p in items:
            print(f"  - {p}")

    print("Scan results:")
    _section("ADDED", result["added"])
    _section("REMOVED", result["removed"])
    _section("MODIFIED", result["modified"])
    _section("META_CHANGED", result["meta_changed"])


def _exit_code(result) -> int:
    changed = any(result[k] for k in ("added", "removed", "modified", "meta_changed"))
    return 2 if changed else 0


def main(argv=None):
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    cfg_path = Path(args.config)
    base_path = Path(args.baseline)
    log_path = Path(args.log_file) if args.log_file else None

    logger = configure_logging(log_path, verbose=not args.json)

    try:
        cfg = load_config(cfg_path)
    except Exception as e:
        print(f"Failed to read config: {e}", file=sys.stderr)
        return 1

    if args.cmd == "baseline":
        state = _state_from_config(cfg, track_perms=args.track_perms)
        save_json(state, base_path)
        if not args.json:
            print(f"Wrote baseline to {base_path}")
        logger.info("Baseline created at %s with %d files", base_path, len(state))
        return 0

    if args.cmd == "scan":
        try:
            prev = load_json(base_path)
        except Exception as e:
            print(f"Failed to read baseline: {e}", file=sys.stderr)
            return 1
        curr = _state_from_config(cfg, track_perms=args.track_perms)
        result = diff_states(prev, curr, strict_mtime=args.strict_mtime)
        _print_or_json(result, as_json=args.json)
        code = _exit_code(result)
        if code == 2:
            logger.warning("Changes detected: %s", {k: len(v) for k, v in result.items()})
        else:
            logger.info("No changes detected")
        return code

    if args.cmd == "watch":
        # Initial load
        try:
            prev = load_json(base_path)
        except Exception as e:
            print(f"Failed to read baseline: {e}", file=sys.stderr)
            return 1
        interval = max(1, args.interval)
        if not args.json:
            print(f"Watching every {interval}s. Press Ctrl+C to stop.")
        while True:
            curr = _state_from_config(cfg, track_perms=args.track_perms)
            result = diff_states(prev, curr, strict_mtime=args.strict_mtime)
            if any(result.values()):
                _print_or_json(result, as_json=args.json)
                logger.warning("Changes detected: %s", {k: len(v) for k, v in result.items()})
                prev = curr  # update baseline in-memory; do not auto-write file
            else:
                if not args.json:
                    print(".", end="", flush=True)
                logger.info("No changes detected")
            time.sleep(interval)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
