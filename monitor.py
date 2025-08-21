"""
Core scanning and baseline logic for the File Integrity Monitor.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import os
import stat
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple


CHUNK_SIZE = 1024 * 1024  # 1MB


def _is_hidden(path: Path) -> bool:
    # Hidden if any part starts with '.' (Unix/Mac); Windows uses 'hidden' attribute but we keep simple.
    return any(part.startswith('.') for part in path.parts)


def _should_exclude(path: Path, patterns: List[str], roots: List[Path]) -> bool:
    """
    Check exclude patterns against:
      - the absolute path
      - the basename
      - the path relative to each root (if possible)
    """
    if not patterns:
        return False

    s_abs = str(path)
    base = path.name

    def match_any(s: str) -> bool:
        return any(fnmatch.fnmatch(s, pat) for pat in patterns)

    if match_any(base) or match_any(s_abs):
        return True

    for root in roots:
        try:
            rel = str(path.relative_to(root))
            if match_any(rel):
                return True
        except ValueError:
            continue
    return False


def hash_file(filepath: Path, algorithm: str = "sha256") -> str:
    try:
        h = hashlib.new(algorithm)
    except Exception as e:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}") from e

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


@dataclass
class FileInfo:
    hash: str
    size: int
    mtime: float
    mode: Optional[int] = None  # permission bits

    @classmethod
    def from_path(cls, p: Path, algorithm: str, track_perms: bool = False) -> "FileInfo":
        st = p.stat()
        file_hash = hash_file(p, algorithm)
        mode = stat.S_IMODE(st.st_mode) if track_perms else None
        return cls(hash=file_hash, size=st.st_size, mtime=st.st_mtime, mode=mode)


def iter_files(paths: Iterable[Path], excludes: List[str], follow_symlinks: bool,
               ignore_hidden: bool) -> Iterator[Path]:
    roots = [p.resolve() for p in paths]

    for root in roots:
        if root.is_file():
            if (not ignore_hidden or not _is_hidden(root)) and not _should_exclude(root, excludes, roots):
                yield root
            continue

        for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
            dpath = Path(dirpath)

            # filter hidden directories early if ignoring hidden
            if ignore_hidden:
                dirnames[:] = [d for d in dirnames if not d.startswith('.')]

            for fname in filenames:
                fpath = dpath / fname
                if ignore_hidden and _is_hidden(fpath):
                    continue
                if _should_exclude(fpath, excludes, roots):
                    continue
                try:
                    if fpath.is_file():
                        yield fpath
                except OSError:
                    # permission or race; skip
                    continue


def build_baseline(paths: List[Path], excludes: List[str], algorithm: str, follow_symlinks: bool,
                   ignore_hidden: bool, track_perms: bool = False) -> Dict[str, Dict]:
    roots = [p.resolve() for p in paths]
    baseline: Dict[str, Dict] = {}
    for fpath in iter_files(roots, excludes, follow_symlinks, ignore_hidden):
        try:
            info = FileInfo.from_path(fpath, algorithm, track_perms=track_perms)
            baseline[str(fpath)] = asdict(info)
        except (PermissionError, FileNotFoundError, OSError):
            continue
    return baseline


def diff_states(prev: Dict[str, Dict], curr: Dict[str, Dict], strict_mtime: bool = False) -> Dict[str, List[str]]:
    prev_keys = set(prev.keys())
    curr_keys = set(curr.keys())

    added = sorted(curr_keys - prev_keys)
    removed = sorted(prev_keys - curr_keys)
    modified = []
    meta_changed = []

    for path in sorted(prev_keys & curr_keys):
        p = prev[path]
        c = curr[path]
        if p["hash"] != c["hash"]:
            modified.append(path)
        else:
            # same content; check metadata drift
            if p.get("size") != c.get("size") or (strict_mtime and p.get("mtime") != c.get("mtime")) or (p.get("mode") != c.get("mode")):
                meta_changed.append(path)

    return {
        "added": added,
        "removed": removed,
        "modified": modified,
        "meta_changed": meta_changed,
    }


def save_json(data: Dict, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def load_json(path: Path) -> Dict:
    with open(path, "r") as f:
        return json.load(f)


def load_config(cfg_path: Path) -> Dict:
    with open(cfg_path, "r") as f:
        cfg = json.load(f)
    # Defaults
    cfg.setdefault("paths", ["./"])
    cfg.setdefault("excludes", [])
    cfg.setdefault("algorithm", "sha256")
    cfg.setdefault("follow_symlinks", False)
    cfg.setdefault("ignore_hidden", True)
    return cfg


def configure_logging(log_file: Optional[Path] = None, verbose: bool = True):
    import logging.handlers as handlers

    logger = logging.getLogger("fim")
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    if verbose:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        logger.addHandler(sh)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = handlers.RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger
