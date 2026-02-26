#!/usr/bin/env python3

import argparse
import json
import re
import sys
from pathlib import Path

SECRET_TYPE_RE = re.compile(r"(secret|private|seed)", re.IGNORECASE)
SECRET_FIELD_RE = re.compile(
    r"(secret|seed|priv|private|secret_key|secretkey|(^|_)sk(_|$))", re.IGNORECASE
)


def load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        print(f"error: failed to read rustdoc json from {path}: {exc}", file=sys.stderr)
        sys.exit(2)


def full_path(paths, item_id: int):
    p = paths.get(str(item_id))
    if not p:
        return None
    return "::".join(p["path"])


def collect_zeroize_impls(index):
    zeroize_ids = set()
    for item in index.values():
        impl = item.get("inner", {}).get("impl")
        if not impl:
            continue
        trait = impl.get("trait")
        if not trait:
            continue
        if trait.get("path") in ("Zeroize", "ZeroizeOnDrop"):
            for_ty = impl.get("for")
            if for_ty and "resolved_path" in for_ty:
                zeroize_ids.add(for_ty["resolved_path"]["id"])
    return zeroize_ids


def type_is_zeroized(ty, zeroize_ids):
    if not isinstance(ty, dict):
        return False

    if "resolved_path" in ty:
        path = ty["resolved_path"]["path"]
        name = path.split("::")[-1]
        if name == "Zeroizing":
            return True
        if ty["resolved_path"]["id"] in zeroize_ids:
            return True
        return False

    if "borrowed_ref" in ty:
        return type_is_zeroized(ty["borrowed_ref"]["type"], zeroize_ids)

    if "array" in ty:
        return type_is_zeroized(ty["array"]["type"], zeroize_ids)

    if "slice" in ty:
        return type_is_zeroized(ty["slice"]["type"], zeroize_ids)

    if "tuple" in ty:
        elems = ty["tuple"]
        return all(type_is_zeroized(elem, zeroize_ids) for elem in elems)

    return False


def struct_fields(index, item):
    fields = []
    kind = item["inner"]["struct"]["kind"]

    if "plain" in kind:
        field_ids = kind["plain"]["fields"]
    elif "tuple" in kind:
        field_ids = kind["tuple"]
    else:
        return fields

    for fid in field_ids:
        field = index[str(fid)]
        field_type = field["inner"]["struct_field"]
        fields.append((field.get("name") or "", field_type, field))

    return fields


def main():
    parser = argparse.ArgumentParser(description="Zeroize audit using rustdoc JSON")
    parser.add_argument("json_path", type=Path)
    args = parser.parse_args()

    obj = load_json(args.json_path)
    index = obj["index"]
    paths = obj["paths"]

    zeroize_ids = collect_zeroize_impls(index)

    failures = []
    scanned = []

    for item in index.values():
        if "struct" not in item.get("inner", {}):
            continue

        name = item.get("name") or ""
        is_secret_named = bool(SECRET_TYPE_RE.search(name))

        fields = struct_fields(index, item)
        secret_fields = [f for f in fields if SECRET_FIELD_RE.search(f[0] or "")]
        is_field_secret = bool(secret_fields)

        if not (is_secret_named or is_field_secret):
            continue

        item_id = item["id"]
        item_path = full_path(paths, item_id) or name
        span = item.get("span") or {}
        loc = f"{span.get('filename', '<unknown>')}:{span.get('begin', ['?'])[0]}"

        has_zeroize_impl = item_id in zeroize_ids

        if has_zeroize_impl:
            scanned.append((item_path, loc, "ok", "impl Zeroize/ZeroizeOnDrop"))
            continue

        if is_field_secret:
            all_secret_zeroized = all(type_is_zeroized(f[1], zeroize_ids) for f in secret_fields)
            if all_secret_zeroized:
                scanned.append((item_path, loc, "ok", "secret fields wrapped/zeroized"))
                continue

        failures.append((item_path, loc, "missing Zeroize"))

    print("Zeroize audit results:")
    for item_path, loc, status, reason in scanned:
        print(f"- {item_path} ({loc}): {status} ({reason})")

    if failures:
        print("\nMissing Zeroize on secret-bearing types:", file=sys.stderr)
        for item_path, loc, reason in failures:
            print(f"- {item_path} ({loc}): {reason}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
