import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path


_DEFAULT_PACK_PATH = (
    Path(__file__).resolve().parent.parent / "skills" / "default_domain_pack.json"
)


def resolve_domain_pack_path(pack_path=None):
    raw_path = pack_path or os.getenv("DOMAIN_PACK_PATH")
    if raw_path and str(raw_path).strip():
        return Path(raw_path).expanduser().resolve()
    return _DEFAULT_PACK_PATH.resolve()


@lru_cache(maxsize=8)
def _load_cached_pack(resolved_path_str):
    path = Path(resolved_path_str)
    if not path.exists():
        raise FileNotFoundError(f"Domain pack configuration file not found: {path}")

    raw_bytes = path.read_bytes()
    digest = hashlib.sha256(raw_bytes).hexdigest()
    data = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Domain pack at {path} must be a JSON object.")

    return data, digest


def load_domain_pack(pack_path=None):
    """Load the active Domain Pack (Skills configuration) and return its dict."""
    resolved = resolve_domain_pack_path(pack_path)
    data, _ = _load_cached_pack(str(resolved))
    return data


def get_domain_pack_metadata(pack_path=None):
    """Return version, path, and SHA-256 fingerprint for run observability."""
    resolved = resolve_domain_pack_path(pack_path)
    data, digest = _load_cached_pack(str(resolved))
    return {
        "pack_name": data.get("pack_name", "unnamed_domain_pack"),
        "version": data.get("version", "0.0.0"),
        "path": str(resolved),
        "sha256": digest,
    }
