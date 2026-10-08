#!/usr/bin/env python3
"""NUM 4 deterministic gate runner.

This script does not attribute coins. It enforces state transitions and validates
machine-readable geometry-gate configs/proposals produced from canonical SPECs.
Canonical nummismatic meaning remains in coins4 instructions/SPEC files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.8.0"
PASS = "PASS"
STOP = "STOP"
REWORK = "REWORK"
HARD_STOP = "HARD_STOP"
DEFAULT_MAX_REWORK_ATTEMPTS = 3

REWORK_RULES = {
    "PREALIGN_LANDMARK_RESIDUAL": ("GEOMETER", "PREALIGN_PASS"),
    "PREALIGN_ROUNDNESS": ("GEOMETER", "PREALIGN_PASS"),
    "PREALIGN_RIM_RESIDUAL": ("GEOMETER", "PREALIGN_PASS"),
    "PREALIGN_RIM_NOT_EVIDENCED": ("GEOMETER", "PREALIGN_PASS"),
    "BAD_PROVENANCE": ("GEOMETER", "GEOMETRY_PASS"),
    "POST_TRANSFORM_FORBIDDEN": ("GEOMETER", "GEOMETRY_PASS"),
    "ZONE_NOT_FOUND": ("GEOMETER", "GEOMETRY_PASS"),
    "COIN_POINTS_INVALID": ("GEOMETER", "GEOMETRY_PASS"),
    "DEGENERATE_POINTS": ("GEOMETER", "GEOMETRY_PASS"),
    "CONTROL_RESIDUAL": ("GEOMETER", "GEOMETRY_PASS"),
    "DEFORMATION_LIMIT": ("GEOMETER", "GEOMETRY_PASS"),
    "VALIDATION_POINTS_MISSING": ("GEOMETER", "GEOMETRY_PASS"),
    "VALIDATION_POINT_INVALID": ("GEOMETER", "GEOMETRY_PASS"),
    "VALIDATION_RESIDUAL": ("GEOMETER", "GEOMETRY_PASS"),
    "VALIDATION_POINT_UNEXPECTED": ("GEOMETER", "GEOMETRY_PASS"),
    "VALIDATION_REFERENCE_NOT_ALLOWED": ("GEOMETER", "GEOMETRY_PASS"),
    "AUDIT_GEOMETRY_REJECTED": ("GEOMETER", "GEOMETRY_PASS"),
    "AUDIT_DIAGNOSTIC_REJECTED": ("DIAGNOSTICIAN", "DIAGNOSTICS_PASS"),
    "DIAGNOSTIC_REASONING_INCOMPLETE": ("DIAGNOSTICIAN", "DIAGNOSTICS_PASS"),
    "AUDIT_ALTERNATIVE_NOT_EXCLUDED": ("DIAGNOSTICIAN", "ALTERNATIVES_PASS"),
    "ALTERNATIVE_NOT_EXCLUDED": ("DIAGNOSTICIAN", "ALTERNATIVES_PASS"),
}

HARD_STOP_CODES = {
    "PREALIGN_NOT_PASS", "PREALIGN_BINDING_MISMATCH", "PREALIGN_INVALID", "PREALIGN_MODEL_INVALID", "PREALIGN_HASH_MISMATCH",
    "PREALIGN_PROVENANCE_INVALID", "PREALIGN_IMAGE_MISMATCH", "PREALIGN_MATRIX_MISMATCH",
    "PREALIGN_REFERENCE_NOT_CIRCULAR", "PREALIGN_DIAGNOSTIC_LEAKAGE",
    "PREALIGN_LANDMARKS_INVALID", "PREALIGN_LANDMARKS_MISSING", "PREALIGN_CANVAS_MISMATCH",
    "REFERENCE_CANVAS_MISMATCH", "CONFIG_NOT_PASS", "CONFIG_MISSING", "CONFIG_INVALID", "NO_ZONES",
    "CONTROL_POINTS_INVALID", "REGION_INVALID", "LEGACY_DIAGNOSTIC_ZONE_FIELD", "POST_TRANSFORM_POLICY",
    "VALIDATION_CONFIG_MISSING", "VALIDATION_CONFIG_INVALID", "TRANSFORM_MODEL_UNSUPPORTED",
    "SPEC_HASH_MISMATCH", "REFERENCE_HASH_MISMATCH",
    "KNOWN_INPUT_DISAPPEARED", "KNOWN_INPUT_CHANGED",
    "RUN_FILES_MISSING", "RUN_NOT_ACTIVE", "SOURCE_CONTRADICTION",
    "SPEC_CONTRADICTION", "CANONICAL_SOURCE_MISSING",
    "ARTIFACT_HASH_MISMATCH", "PHOTO_INSUFFICIENT",
    "REQUIRED_MEASUREMENT_MISSING", "RUN_DIR_NOT_EMPTY",
    "SNAPSHOT_INVALID", "BAD_CLOSE_MODE", "VERDICT_FILE_MISSING",
    "VALID_VERDICT_RECEIPT_REQUIRED",
}

USER_ACTION_HARD_STOP_CODES = {
    "PREALIGN_NOT_PASS", "PREALIGN_BINDING_MISMATCH", "PREALIGN_INVALID", "PREALIGN_MODEL_INVALID", "PREALIGN_HASH_MISMATCH",
    "PREALIGN_PROVENANCE_INVALID", "PREALIGN_IMAGE_MISMATCH", "PREALIGN_MATRIX_MISMATCH",
    "PREALIGN_REFERENCE_NOT_CIRCULAR", "PREALIGN_DIAGNOSTIC_LEAKAGE",
    "PREALIGN_LANDMARKS_INVALID", "PREALIGN_LANDMARKS_MISSING", "PREALIGN_CANVAS_MISMATCH",
    "REFERENCE_CANVAS_MISMATCH", "CONFIG_NOT_PASS", "CONFIG_MISSING", "CONFIG_INVALID", "NO_ZONES",
    "CONTROL_POINTS_INVALID", "REGION_INVALID", "LEGACY_DIAGNOSTIC_ZONE_FIELD", "POST_TRANSFORM_POLICY",
    "VALIDATION_CONFIG_MISSING", "VALIDATION_CONFIG_INVALID", "TRANSFORM_MODEL_UNSUPPORTED",
    "SPEC_HASH_MISMATCH", "REFERENCE_HASH_MISMATCH",
    "KNOWN_INPUT_DISAPPEARED", "KNOWN_INPUT_CHANGED",
    "SOURCE_CONTRADICTION", "SPEC_CONTRADICTION",
    "CANONICAL_SOURCE_MISSING", "ARTIFACT_HASH_MISMATCH",
    "PHOTO_INSUFFICIENT", "REQUIRED_MEASUREMENT_MISSING",
}

REQUIRED_VERDICT_GATES = [
    "SOURCES_PASS",
    "BRANCH_PASS",
    "PREALIGN_PASS",
    "GEOMETRY_PASS",
    "DIAGNOSTICS_PASS",
    "ALTERNATIVES_PASS",
    "AUDIT_PASS",
]


RUN_GATES = [
    "SOURCES_PASS",
    "BRANCH_PASS",
    "PREALIGN_PASS",
    "GEOMETRY_PASS",
    "DIAGNOSTICS_PASS",
    "ALTERNATIVES_PASS",
    "AUDIT_PASS",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_run_id(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    if not value or value in {".", ".."}:
        raise ValueError("invalid RUN_ID")
    return value[:120]


def _validate_snapshot(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    files = snapshot.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("snapshot.files must be a non-empty list")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for i, item in enumerate(files):
        if not isinstance(item, dict):
            raise ValueError(f"snapshot.files[{i}] must be an object")
        fid = str(item.get("id") or "").strip()
        name = str(item.get("name") or item.get("title") or "").strip()
        sha = str(item.get("sha256") or "").strip().lower()
        size = item.get("size")
        if not fid or not name:
            raise ValueError(f"snapshot.files[{i}] requires id and name")
        if fid in seen:
            raise ValueError(f"duplicate input file id: {fid}")
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError(f"snapshot.files[{i}] requires a 64-hex sha256")
        try:
            size_i = int(size)
        except (TypeError, ValueError):
            raise ValueError(f"snapshot.files[{i}] requires integer size")
        if size_i < 0:
            raise ValueError(f"snapshot.files[{i}] size must be >= 0")
        seen.add(fid)
        normalized.append({
            "id": fid,
            "name": name,
            "size": size_i,
            "sha256": sha,
        })
    normalized.sort(key=lambda x: (x["name"], x["id"]))
    return normalized


def _default_run_id(files: list[dict[str, Any]], created_at: str) -> str:
    seed = sha256_obj({"ids": sorted(x["id"] for x in files)})[:10]
    stamp = re.sub(r"[^0-9]", "", created_at)[:14] or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"RUN_{stamp}_{seed}"


def _pointer(run_id: str | None, status: str, manifest_sha256: str | None, updated_at: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "active_run_id": run_id,
        "status": status,
        "manifest_sha256": manifest_sha256,
        "updated_at": updated_at,
    }


def initialize_run(snapshot: dict[str, Any], output_dir: str | Path, run_id: str | None = None, created_at: str | None = None) -> dict[str, Any]:
    files = _validate_snapshot(snapshot)
    created_at = created_at or utc_now_iso()
    run_id = _safe_run_id(run_id or _default_run_id(files, created_at))
    out = Path(output_dir)
    if out.exists() and any(out.iterdir()):
        return {"gate": "RUN_INIT", "result": STOP, "reason": "RUN_DIR_NOT_EMPTY", "run_id": run_id}
    out.mkdir(parents=True, exist_ok=True)

    manifest = {
        "schema_version": "1.0",
        "run_id": run_id,
        "status": "ACTIVE",
        "catalog_root": "/coins4",
        "inbox_folder_id": snapshot.get("inbox_folder_id"),
        "created_at": created_at,
        "updated_at": created_at,
        "input_revision": 1,
        "files": files,
        "canonical_sources": {},
        "branch": {"status": "PENDING"},
    }
    manifest_hash = sha256_obj(manifest)
    state = {
        "schema_version": "1.0",
        "run_id": run_id,
        "status": "ACTIVE",
        "updated_at": created_at,
        "manifest_sha256": manifest_hash,
        "gates": {g: "PENDING" for g in RUN_GATES},
        "artifacts": {"manifest.json": manifest_hash},
        "VERDICT_RECEIPT": None,
        "workflow_status": "ACTIVE",
        "max_rework_attempts": DEFAULT_MAX_REWORK_ATTEMPTS,
        "rework_counters": {},
        "review_history": [],
        "last_review_decision": None,
    }
    write_json(out / "manifest.json", manifest)
    write_json(out / "run_state.json", state)
    pointer = _pointer(run_id, "ACTIVE", manifest_hash, created_at)
    return {
        "gate": "RUN_INIT",
        "result": PASS,
        "run_id": run_id,
        "run_dir": str(out),
        "manifest_sha256": manifest_hash,
        "pointer": pointer,
        "created_files": ["manifest.json", "run_state.json"],
    }


def sync_run_inputs(run_dir: str | Path, snapshot: dict[str, Any], updated_at: str | None = None) -> dict[str, Any]:
    run_dir = Path(run_dir)
    manifest_path = run_dir / "manifest.json"
    state_path = run_dir / "run_state.json"
    if not manifest_path.exists() or not state_path.exists():
        return {"gate": "RUN_SYNC", "result": STOP, "reason": "RUN_FILES_MISSING"}
    manifest = load_json(manifest_path)
    state = load_json(state_path)
    if manifest.get("status") != "ACTIVE" or state.get("status") != "ACTIVE":
        return {"gate": "RUN_SYNC", "result": STOP, "reason": "RUN_NOT_ACTIVE"}
    current = _validate_snapshot(snapshot)
    old_by_id = {x["id"]: x for x in manifest.get("files", [])}
    cur_by_id = {x["id"]: x for x in current}
    missing = sorted(set(old_by_id) - set(cur_by_id))
    if missing:
        return {
            "gate": "RUN_SYNC",
            "result": STOP,
            "reason": "KNOWN_INPUT_DISAPPEARED",
            "missing_ids": missing,
        }
    changed_existing = [fid for fid in old_by_id if old_by_id[fid] != cur_by_id[fid]]
    if changed_existing:
        return {
            "gate": "RUN_SYNC",
            "result": STOP,
            "reason": "KNOWN_INPUT_CHANGED",
            "changed_ids": sorted(changed_existing),
        }
    new_ids = sorted(set(cur_by_id) - set(old_by_id))
    if not new_ids:
        return {
            "gate": "RUN_SYNC",
            "result": PASS,
            "run_id": manifest.get("run_id"),
            "changed": False,
            "manifest_sha256": sha256_obj(manifest),
            "pointer": _pointer(manifest.get("run_id"), "ACTIVE", sha256_obj(manifest), manifest.get("updated_at") or utc_now_iso()),
        }

    updated_at = updated_at or utc_now_iso()
    manifest["files"] = current
    manifest["input_revision"] = int(manifest.get("input_revision", 1)) + 1
    manifest["updated_at"] = updated_at
    manifest_hash = sha256_obj(manifest)
    state["updated_at"] = updated_at
    state["manifest_sha256"] = manifest_hash
    state["gates"] = {g: "PENDING" for g in RUN_GATES}
    state["VERDICT_RECEIPT"] = None
    state["artifacts"] = {"manifest.json": manifest_hash}
    state["workflow_status"] = "ACTIVE"
    state["rework_counters"] = {}
    state["last_review_decision"] = None
    state["invalidation_reason"] = "INPUTS_CHANGED"
    write_json(manifest_path, manifest)
    write_json(state_path, state)
    return {
        "gate": "RUN_SYNC",
        "result": PASS,
        "run_id": manifest.get("run_id"),
        "changed": True,
        "added_ids": new_ids,
        "manifest_sha256": manifest_hash,
        "pointer": _pointer(manifest.get("run_id"), "ACTIVE", manifest_hash, updated_at),
    }


def close_run(run_dir: str | Path, mode: str, updated_at: str | None = None) -> dict[str, Any]:
    run_dir = Path(run_dir)
    manifest_path = run_dir / "manifest.json"
    state_path = run_dir / "run_state.json"
    if not manifest_path.exists() or not state_path.exists():
        return {"gate": "RUN_CLOSE", "result": STOP, "reason": "RUN_FILES_MISSING"}
    manifest = load_json(manifest_path)
    state = load_json(state_path)
    mode = mode.upper()
    if mode not in {"VERDICT", "ABORT"}:
        return {"gate": "RUN_CLOSE", "result": STOP, "reason": "BAD_CLOSE_MODE"}
    if mode == "VERDICT":
        verdict_path = run_dir / "verdict.json"
        if not verdict_path.exists():
            return {"gate": "RUN_CLOSE", "result": STOP, "reason": "VERDICT_FILE_MISSING"}
        verdict = load_json(verdict_path)
        if verdict.get("result") != PASS or not verdict.get("VERDICT_RECEIPT"):
            return {"gate": "RUN_CLOSE", "result": STOP, "reason": "VALID_VERDICT_RECEIPT_REQUIRED"}
    updated_at = updated_at or utc_now_iso()
    final_status = "CLOSED" if mode == "VERDICT" else "ABORTED"
    manifest["status"] = final_status
    manifest["updated_at"] = updated_at
    manifest_hash = sha256_obj(manifest)
    state["status"] = final_status
    state["updated_at"] = updated_at
    state["manifest_sha256"] = manifest_hash
    write_json(manifest_path, manifest)
    write_json(state_path, state)
    return {
        "gate": "RUN_CLOSE",
        "result": PASS,
        "run_id": manifest.get("run_id"),
        "status": final_status,
        "manifest_sha256": manifest_hash,
        "pointer": _pointer(None, "NONE", None, updated_at),
    }


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_obj(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def load_json(path: str | Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str | Path, obj: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def is_tbd(v: Any) -> bool:
    return v is None or (isinstance(v, str) and v.strip().upper() in {"TBD", "TODO", "UNKNOWN", "UNSET", ""})


def _is_num_pair(p: Any) -> bool:
    return isinstance(p, list) and len(p) == 2 and all(isinstance(x, (int, float)) and math.isfinite(x) for x in p)


def lint_geometry_config(cfg: dict[str, Any]) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    missing: list[str] = []

    def req(name: str, val: Any) -> None:
        if is_tbd(val):
            missing.append(name)

    def req_nonneg_number(name: str, val: Any) -> None:
        req(name, val)
        if not is_tbd(val):
            if not isinstance(val, (int, float)) or not math.isfinite(float(val)) or float(val) < 0:
                issues.append({"code": "CONFIG_INVALID", "message": f"{name} must be a finite number >= 0"})

    req("schema_version", cfg.get("schema_version"))
    req("canonical_spec_file_id", cfg.get("canonical_spec_file_id"))
    req("canonical_spec_sha256", cfg.get("canonical_spec_sha256"))
    req("reference_file_id", cfg.get("reference_file_id"))
    req("reference_sha256", cfg.get("reference_sha256"))
    req("canvas", cfg.get("canvas"))
    req("transform_model", cfg.get("transform_model"))
    req_nonneg_number("max_control_residual_px", cfg.get("max_control_residual_px"))
    req_nonneg_number("max_validation_residual_px", cfg.get("max_validation_residual_px"))
    req_nonneg_number("max_allowed_deformation", cfg.get("max_allowed_deformation"))

    canvas=cfg.get("canvas")
    if not (isinstance(canvas,list) and len(canvas)==2 and all(isinstance(x,(int,float)) and math.isfinite(float(x)) and float(x)>0 for x in canvas)):
        issues.append({"code":"CONFIG_INVALID","message":"canvas must be [width,height] with positive numeric values"})
        canvas=None

    model = cfg.get("transform_model")
    if not is_tbd(model) and model not in {"SIMILARITY_LS_3PT", "AFFINE_3PT"}:
        issues.append({"code": "TRANSFORM_MODEL_UNSUPPORTED", "message": f"unsupported transform_model: {model!r}"})

    legacy_top=[k for k in ("diagnostic_roi","roi_must_be_strictly_inside_control_bbox","roi_policy","diagnostic_mask","diagnostic_polygon") if k in cfg]
    if legacy_top:
        issues.append({"code":"LEGACY_DIAGNOSTIC_ZONE_FIELD","message":"legacy diagnostic-zone fields are forbidden: "+", ".join(legacy_top)})

    zones = cfg.get("zones")
    if not isinstance(zones, list) or not zones:
        issues.append({"code": "NO_ZONES", "message": "zones must be a non-empty list"})
        zones = []

    for i, z in enumerate(zones):
        if not isinstance(z, dict):
            issues.append({"code": "CONFIG_INVALID", "message": f"zones[{i}] must be an object"})
            continue
        label = str(z.get("id", i + 1))
        pts = z.get("reference_points")
        if not isinstance(pts, list) or len(pts) != 3 or not all(_is_num_pair(p) for p in pts):
            issues.append({"code": "CONTROL_POINTS_INVALID", "message": f"zone {label}: exactly 3 numeric reference_points required"})

        legacy=[k for k in ("diagnostic_roi","roi_must_be_strictly_inside_control_bbox","roi_policy","diagnostic_mask","diagnostic_polygon") if k in z]
        if legacy:
            issues.append({"code":"LEGACY_DIAGNOSTIC_ZONE_FIELD","message":f"zone {label}: legacy diagnostic-zone fields are forbidden: "+", ".join(legacy)})

        region=z.get("diagnostic_region")
        if is_tbd(region):
            issues.append({"code":"CONFIG_MISSING","message":f"zone {label}: diagnostic_region is not manually approved yet"})
        elif not isinstance(region,dict):
            issues.append({"code":"REGION_INVALID","message":f"zone {label}: diagnostic_region must be an object"})
        else:
            if region.get("type") != "BINARY_MASK_RLE":
                issues.append({"code":"REGION_INVALID","message":f"zone {label}: diagnostic_region.type must be BINARY_MASK_RLE"})
            if region.get("source") != "USER_MARKUP_FULL_REFERENCE":
                issues.append({"code":"REGION_INVALID","message":f"zone {label}: diagnostic_region.source must be USER_MARKUP_FULL_REFERENCE"})
            if region.get("approved") is not True:
                issues.append({"code":"REGION_INVALID","message":f"zone {label}: diagnostic_region must be approved=true"})
            rcanvas=region.get("canvas")
            if canvas is None or rcanvas != cfg.get("canvas"):
                issues.append({"code":"REGION_INVALID","message":f"zone {label}: diagnostic_region.canvas must equal config canvas"})
            runs=region.get("runs")
            if not isinstance(runs,list) or not runs:
                issues.append({"code":"REGION_INVALID","message":f"zone {label}: diagnostic_region.runs must be a non-empty list"})
            elif canvas is not None:
                total=int(canvas[0])*int(canvas[1])
                prev_end=-1
                for j,run in enumerate(runs):
                    if not (isinstance(run,list) and len(run)==2 and all(isinstance(v,int) and not isinstance(v,bool) for v in run)):
                        issues.append({"code":"REGION_INVALID","message":f"zone {label}: runs[{j}] must be [integer_start, integer_length]"})
                        continue
                    st,ln=run
                    if st < 0 or ln <= 0 or st+ln > total:
                        issues.append({"code":"REGION_INVALID","message":f"zone {label}: runs[{j}] is outside canvas or has non-positive length"})
                    if st <= prev_end:
                        issues.append({"code":"REGION_INVALID","message":f"zone {label}: diagnostic_region runs must be sorted and non-overlapping"})
                    prev_end=max(prev_end,st+ln-1)

        vals = z.get("validation_points", cfg.get("validation_points"))
        if is_tbd(vals) or not isinstance(vals, list) or not vals:
            issues.append({"code": "VALIDATION_CONFIG_MISSING", "message": f"zone {label}: fixed validation_points are required"})
        else:
            seen_ids: set[str] = set()
            for j, item in enumerate(vals):
                if not isinstance(item, dict):
                    issues.append({"code": "VALIDATION_CONFIG_INVALID", "message": f"zone {label}: validation_points[{j}] must be an object"})
                    continue
                vid = str(item.get("id") or "").strip()
                ref = item.get("reference")
                if not vid or vid in seen_ids or not _is_num_pair(ref):
                    issues.append({"code": "VALIDATION_CONFIG_INVALID", "message": f"zone {label}: each validation point requires unique id and fixed numeric reference coordinates"})
                    continue
                seen_ids.add(vid)

    if cfg.get("post_transform_policy") != "FORBID":
        issues.append({"code": "POST_TRANSFORM_POLICY", "message": "post_transform_policy must be FORBID"})

    if missing:
        for name in missing:
            issues.append({"code": "CONFIG_MISSING", "message": f"missing/TBD: {name}"})

    return {
        "gate": "GEOMETRY_CONFIG",
        "result": PASS if not issues else STOP,
        "config_sha256": sha256_obj(cfg),
        "issues": issues,
    }



def verify_binding(cfg: dict[str, Any], spec_file: str | Path, reference_file: str | Path) -> dict[str, Any]:
    issues: list[dict[str, str]] = []
    spec_actual = sha256_file(spec_file)
    ref_actual = sha256_file(reference_file)
    if cfg.get("canonical_spec_sha256") != spec_actual:
        issues.append({"code": "SPEC_HASH_MISMATCH", "message": f"expected {cfg.get('canonical_spec_sha256')}, got {spec_actual}"})
    if cfg.get("reference_sha256") != ref_actual:
        issues.append({"code": "REFERENCE_HASH_MISMATCH", "message": f"expected {cfg.get('reference_sha256')}, got {ref_actual}"})
    return {
        "gate": "SOURCE_BINDING",
        "result": PASS if not issues else STOP,
        "spec_sha256": spec_actual,
        "reference_sha256": ref_actual,
        "issues": issues,
    }

def _solve_linear(A: list[list[float]], b: list[float]) -> list[float]:
    n = len(b)
    aug = [list(map(float, A[r])) + [float(b[r])] for r in range(n)]
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(aug[r][col]))
        if abs(aug[pivot][col]) < 1e-12:
            raise ValueError("linear system is singular")
        aug[col], aug[pivot] = aug[pivot], aug[col]
        pv = aug[col][col]
        aug[col] = [v / pv for v in aug[col]]
        for r in range(n):
            if r == col:
                continue
            f = aug[r][col]
            aug[r] = [aug[r][c] - f * aug[col][c] for c in range(n + 1)]
    return [aug[i][-1] for i in range(n)]


def similarity_from_points(src: list[list[float]], dst: list[list[float]]) -> list[list[float]]:
    """Least-squares orientation-preserving similarity: rotation + uniform scale + translation."""
    if len(src) != len(dst) or len(src) < 2:
        raise ValueError("similarity transform requires at least 2 point pairs")
    rows: list[list[float]] = []
    rhs: list[float] = []
    for (x, y), (u, v) in zip(src, dst):
        rows.append([x, -y, 1.0, 0.0]); rhs.append(u)
        rows.append([y,  x, 0.0, 1.0]); rhs.append(v)
    ata = [[0.0] * 4 for _ in range(4)]
    atb = [0.0] * 4
    for row, val in zip(rows, rhs):
        for i in range(4):
            atb[i] += row[i] * val
            for j in range(4):
                ata[i][j] += row[i] * row[j]
    a, b, tx, ty = _solve_linear(ata, atb)
    scale = math.hypot(a, b)
    if not math.isfinite(scale) or scale <= 1e-12:
        raise ValueError("similarity transform is degenerate")
    return [[a, -b, tx], [b, a, ty]]


def affine_from_3(src: list[list[float]], dst: list[list[float]]) -> list[list[float]]:
    # Solve x' = ax + by + c ; y' = dx + ey + f with Gaussian elimination.
    A = []
    b = []
    for (x, y), (u, v) in zip(src, dst):
        A.append([x, y, 1.0, 0.0, 0.0, 0.0]); b.append(u)
        A.append([0.0, 0.0, 0.0, x, y, 1.0]); b.append(v)
    n = 6
    aug = [list(map(float, A[r])) + [float(b[r])] for r in range(n)]
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(aug[r][col]))
        if abs(aug[pivot][col]) < 1e-12:
            raise ValueError("control points are degenerate")
        aug[col], aug[pivot] = aug[pivot], aug[col]
        pv = aug[col][col]
        aug[col] = [v / pv for v in aug[col]]
        for r in range(n):
            if r == col:
                continue
            f = aug[r][col]
            aug[r] = [aug[r][c] - f * aug[col][c] for c in range(n + 1)]
    a, b1, c, d, e, f = [aug[i][-1] for i in range(n)]
    return [[a, b1, c], [d, e, f]]


def apply_affine(M: list[list[float]], p: list[float]) -> list[float]:
    x, y = p
    return [M[0][0] * x + M[0][1] * y + M[0][2], M[1][0] * x + M[1][1] * y + M[1][2]]


def dist(a: list[float], b: list[float]) -> float:
    return math.hypot(a[0] - b[0], a[1] - b[1])


def affine_anisotropy(M: list[list[float]]) -> float:
    """Singular-value ratio of the 2x2 affine linear part; 1.0 is isotropic."""
    a, b = M[0][0], M[0][1]
    c, d = M[1][0], M[1][1]
    s11 = a*a + c*c
    s22 = b*b + d*d
    s12 = a*b + c*d
    tr = s11 + s22
    det = s11*s22 - s12*s12
    disc = max(0.0, tr*tr - 4.0*det)
    l1 = max(0.0, (tr + math.sqrt(disc)) / 2.0)
    l2 = max(0.0, (tr - math.sqrt(disc)) / 2.0)
    if l2 <= 1e-15:
        return float("inf")
    return math.sqrt(l1 / l2)


def validate_geometry_proposal(cfg: dict[str, Any], proposal: dict[str, Any], prealign_report:dict[str,Any]|None=None) -> dict[str, Any]:
    cfg_report = lint_geometry_config(cfg)
    if cfg_report["result"] != PASS:
        return {
            "gate": "GEOMETRY",
            "result": STOP,
            "reason": "CONFIG_NOT_PASS",
            "config_report": cfg_report,
        }

    issues: list[dict[str, Any]] = []
    if not isinstance(prealign_report,dict) or prealign_report.get("result")!=PASS or not prealign_report.get("prealign_receipt"):
        issues.append({"code":"PREALIGN_NOT_PASS","message":"valid machine prealign receipt required BEFORE C1-C2-C3 geometry"})
    else:
        if prealign_report.get("config_sha256")!=sha256_obj(cfg) or prealign_report.get("reference_file_id")!=cfg.get("reference_file_id"):
            issues.append({"code":"PREALIGN_BINDING_MISMATCH","message":"prealign receipt belongs to a different canonical configuration"})
        if proposal.get("prealign_receipt")!=prealign_report["prealign_receipt"] or proposal.get("normalized_sha256")!=prealign_report.get("normalized_sha256"):
            issues.append({"code":"PREALIGN_BINDING_MISMATCH","message":"geometry proposal is not bound to the validated normalized image"})
    if proposal.get("transform_provenance") != "C1_C2_C3_ONLY":
        issues.append({"code": "BAD_PROVENANCE", "message": "transform must be derived only from C1-C2-C3"})
    post = proposal.get("post_transforms", [])
    if post not in ([], None):
        issues.append({"code": "POST_TRANSFORM_FORBIDDEN", "message": "any transform after geometry freeze is forbidden"})

    zone_id = proposal.get("zone_id")
    zone = next((z for z in cfg["zones"] if str(z.get("id")) == str(zone_id)), None)
    if zone is None:
        issues.append({"code": "ZONE_NOT_FOUND", "message": f"zone {zone_id!r} is not in config"})
        return {"gate": "GEOMETRY", "result": STOP, "issues": issues}

    src = proposal.get("coin_points")
    dst = zone.get("reference_points")
    if not isinstance(src, list) or len(src) != 3 or not all(_is_num_pair(p) for p in src):
        issues.append({"code": "COIN_POINTS_INVALID", "message": "exactly 3 numeric coin_points required"})
        return {"gate": "GEOMETRY", "result": STOP, "issues": issues}

    model = cfg.get("transform_model")
    try:
        if model == "SIMILARITY_LS_3PT":
            M = similarity_from_points(src, dst)
            deformation_observed = 0.0
            deformation_metric = "similarity_shape_deformation"
        elif model == "AFFINE_3PT":
            M = affine_from_3(src, dst)
            anisotropy = affine_anisotropy(M)
            deformation_observed = anisotropy - 1.0
            deformation_metric = "affine_anisotropy_ratio_minus_1"
        else:
            issues.append({"code": "TRANSFORM_MODEL_UNSUPPORTED", "message": f"configured model {model!r} is not executable"})
            return {"gate": "GEOMETRY", "result": STOP, "issues": issues}
    except ValueError as e:
        issues.append({"code": "DEGENERATE_POINTS", "message": str(e)})
        return {"gate": "GEOMETRY", "result": STOP, "issues": issues}

    residuals = [dist(apply_affine(M, s), d) for s, d in zip(src, dst)]
    max_control = max(residuals)
    control_limit = float(cfg["max_control_residual_px"])
    if max_control > control_limit:
        issues.append({
            "code": "CONTROL_RESIDUAL",
            "message": f"max control residual {max_control:.6f}px exceeds threshold {control_limit:.6f}px",
            "observed": max_control,
            "threshold": control_limit,
            "unit": "px",
        })

    deformation_limit = float(cfg["max_allowed_deformation"])
    if deformation_observed > deformation_limit + 1e-12:
        issues.append({
            "code": "DEFORMATION_LIMIT",
            "message": f"{deformation_metric} {deformation_observed:.6f} exceeds threshold {deformation_limit:.6f}",
            "observed": deformation_observed,
            "threshold": deformation_limit,
            "unit": "ratio_minus_1",
        })

    expected_defs = zone.get("validation_points", cfg.get("validation_points"))
    expected_by_id = {str(x.get("id")): x for x in expected_defs if isinstance(x, dict) and x.get("id")}
    vals = proposal.get("validation_points")
    validation_residuals: list[dict[str, Any]] = []
    if not isinstance(vals, list) or not vals:
        issues.append({"code": "VALIDATION_POINTS_MISSING", "message": "proposal validation_points are required"})
    else:
        provided_ids: set[str] = set()
        maxvr = 0.0
        for item in vals:
            if not isinstance(item, dict):
                issues.append({"code": "VALIDATION_POINT_INVALID", "message": "validation point must be an object with id and coin"})
                continue
            vid = str(item.get("id") or "").strip()
            cp = item.get("coin")
            if "reference" in item:
                issues.append({
                    "code": "VALIDATION_REFERENCE_NOT_ALLOWED",
                    "message": f"validation point {vid or '?'}: reference coordinates must come from canonical config, not proposal",
                })
            if not vid or not _is_num_pair(cp):
                issues.append({"code": "VALIDATION_POINT_INVALID", "message": "validation point must contain id and numeric coin coordinates"})
                continue
            if vid in provided_ids:
                issues.append({"code": "VALIDATION_POINT_INVALID", "message": f"duplicate validation point id: {vid}"})
                continue
            provided_ids.add(vid)
            expected = expected_by_id.get(vid)
            if expected is None:
                issues.append({"code": "VALIDATION_POINT_UNEXPECTED", "message": f"validation point {vid} is not defined by canonical config"})
                continue
            rp = expected.get("reference")
            if not _is_num_pair(rp):
                issues.append({"code": "VALIDATION_CONFIG_INVALID", "message": f"canonical validation point {vid} lacks fixed reference coordinates"})
                continue
            vr = dist(apply_affine(M, cp), rp)
            maxvr = max(maxvr, vr)
            validation_residuals.append({"id": vid, "residual_px": vr})
        missing_ids = sorted(set(expected_by_id) - provided_ids)
        if missing_ids:
            issues.append({
                "code": "VALIDATION_POINTS_MISSING",
                "message": "missing required validation point ids: " + ", ".join(missing_ids),
            })
        validation_limit = float(cfg["max_validation_residual_px"])
        if validation_residuals and maxvr > validation_limit:
            issues.append({
                "code": "VALIDATION_RESIDUAL",
                "message": f"max validation residual {maxvr:.6f}px exceeds threshold {validation_limit:.6f}px",
                "observed": maxvr,
                "threshold": validation_limit,
                "unit": "px",
            })

    out = {
        "gate": "GEOMETRY",
        "result": PASS if not issues else STOP,
        "zone_id": zone_id,
        "transform_model": model,
        "matrix": M,
        "control_residuals_px": residuals,
        "max_control_residual_px": max_control,
        "deformation_metric": deformation_metric,
        "deformation_observed": deformation_observed,
        "validation_residuals": validation_residuals,
        "issues": issues,
        "config_sha256": sha256_obj(cfg),
        "proposal_sha256": sha256_obj(proposal),
        "prealign_receipt": prealign_report.get("prealign_receipt") if isinstance(prealign_report,dict) else None,
    }
    if out["result"] == PASS:
        out["geometry_receipt"] = sha256_obj(out)
    return out



def _extract_review_issues(review: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    raw = review.get("issues")
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                code = str(item.get("code") or "UNKNOWN_FAILURE").strip().upper()
                message = str(item.get("message") or item.get("detail") or code).strip()
                norm = dict(item)
                norm["code"] = code
                norm["message"] = message
                issues.append(norm)
            elif item is not None:
                issues.append({"code": "UNKNOWN_FAILURE", "message": str(item)})
    cfg_report = review.get("config_report")
    if isinstance(cfg_report, dict) and isinstance(cfg_report.get("issues"), list):
        for item in cfg_report["issues"]:
            if isinstance(item, dict):
                code = str(item.get("code") or "CONFIG_NOT_PASS").strip().upper()
                message = str(item.get("message") or code).strip()
                norm = dict(item)
                norm["code"] = code
                norm["message"] = message
                issues.append(norm)
    if not issues and review.get("reason"):
        issues.append({
            "code": str(review.get("reason")).strip().upper(),
            "message": str(review.get("message") or review.get("reason")).strip(),
        })
    if not issues and review.get("missing_or_failed"):
        for gate in review.get("missing_or_failed") or []:
            issues.append({"code": "GATE_NOT_PASS", "message": f"required gate not PASS: {gate}"})
    if not issues:
        issues.append({"code": "UNKNOWN_FAILURE", "message": "review rejected result without a machine-readable reason"})
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in issues:
        key = (item["code"], item["message"])
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _stage_gate(stage: str) -> str | None:
    s = str(stage or "").upper()
    if "SOURCE" in s or s == "ORCHESTRATOR":
        return "SOURCES_PASS"
    if "BRANCH" in s:
        return "BRANCH_PASS"
    if "PREALIGN" in s:
        return "PREALIGN_PASS"
    if "GEOMET" in s or s == "MACHINE_GATE":
        return "GEOMETRY_PASS"
    if "DIAGN" in s:
        return "DIAGNOSTICS_PASS"
    if "ALTERNATIVE" in s:
        return "ALTERNATIVES_PASS"
    if "AUDIT" in s or s == "AUDITOR":
        return "AUDIT_PASS"
    return None


def _invalidate_from(state: dict[str, Any], gate: str | None, marker: str) -> list[str]:
    if gate not in RUN_GATES:
        return []
    start = RUN_GATES.index(gate)
    invalidated = RUN_GATES[start:]
    gates = state.setdefault("gates", {})
    for g in invalidated:
        gates[g] = "PENDING"
    gates[gate] = marker
    state["VERDICT_RECEIPT"] = None
    return invalidated


def route_review(
    run_dir: str | Path,
    review: dict[str, Any],
    max_attempts: int | None = None,
    updated_at: str | None = None,
) -> dict[str, Any]:
    """Route a rejected review to REWORK or HARD_STOP, fail-closed."""
    run_dir = Path(run_dir)
    state_path = run_dir / "run_state.json"
    if not state_path.exists():
        return {
            "gate": "REVIEW_ROUTER", "result": HARD_STOP,
            "reason_codes": ["RUN_FILES_MISSING"],
            "detailed_reason": "run_state.json is missing; review cannot be routed safely",
            "returned_for_rework": False,
        }
    state = load_json(state_path)
    if state.get("status") != "ACTIVE":
        return {
            "gate": "REVIEW_ROUTER", "result": HARD_STOP,
            "reason_codes": ["RUN_NOT_ACTIVE"],
            "detailed_reason": f"RUN status is {state.get('status')!r}, not ACTIVE",
            "returned_for_rework": False,
        }

    reviewer = str(review.get("reviewer") or review.get("gate") or "UNKNOWN_REVIEWER")
    failed_stage = str(review.get("stage") or review.get("gate") or "UNKNOWN_STAGE")
    updated_at = updated_at or utc_now_iso()
    max_attempts = int(max_attempts or state.get("max_rework_attempts") or DEFAULT_MAX_REWORK_ATTEMPTS)
    if max_attempts < 1:
        max_attempts = DEFAULT_MAX_REWORK_ATTEMPTS

    if str(review.get("result") or "").upper() == PASS:
        previous_status = str(state.get("workflow_status") or "ACTIVE").upper()
        history = state.setdefault("review_history", [])
        last = history[-1] if history else None
        if previous_status in {REWORK, HARD_STOP}:
            if not last or str(last.get("reviewer")) != reviewer or str(last.get("failed_stage")) != failed_stage:
                return {
                    "schema_version": "1.0",
                    "gate": "REVIEW_ROUTER",
                    "result": HARD_STOP,
                    "reviewer": reviewer,
                    "failed_stage": failed_stage,
                    "reason_codes": ["UNRELATED_PASS_CANNOT_CLEAR_STOP"],
                    "detailed_reason": "PASS came from a different reviewer/stage and cannot clear the active REWORK/HARD_STOP",
                    "returned_for_rework": False,
                    "target_stage": None,
                    "resume_condition": "Rerun the same reviewer and failed_stage recorded by the last review decision until it returns PASS.",
                    "updated_at": updated_at,
                    "review_sha256": sha256_obj(review),
                }
            invalidated = last.get("invalidated_gates") or []
            if invalidated:
                first_gate = invalidated[0]
                if state.setdefault("gates", {}).get(first_gate) in {REWORK, HARD_STOP}:
                    state["gates"][first_gate] = "PENDING"
            state["workflow_status"] = "ACTIVE"
            state["updated_at"] = updated_at
            seq = len(history) + 1
            filename = f"review_decision_{seq:03d}.json"
            decision = {
                "schema_version": "1.0",
                "gate": "REVIEW_ROUTER",
                "result": PASS,
                "reviewer": reviewer,
                "failed_stage": failed_stage,
                "detailed_reason": f"the same reviewer/stage accepted the replacement after {previous_status}",
                "returned_for_rework": False,
                "target_stage": None,
                "resolved_previous_status": previous_status,
                "resume_condition": "Aggregate gate evaluation may resume from the corrected stage.",
                "updated_at": updated_at,
                "review_sha256": sha256_obj(review),
                "artifact": filename,
            }
            write_json(run_dir / filename, decision)
            decision_hash = sha256_obj(decision)
            history.append({
                "sequence": seq, "artifact": filename, "sha256": decision_hash,
                "result": PASS, "reviewer": reviewer, "failed_stage": failed_stage,
                "reason_codes": [], "target_stage": None, "rework_attempt": None,
                "invalidated_gates": invalidated, "updated_at": updated_at,
            })
            state["last_review_decision"] = {"artifact": filename, "sha256": decision_hash, "result": PASS}
            state.setdefault("artifacts", {})[filename] = decision_hash
            write_json(state_path, state)
            return decision
        return {
            "schema_version": "1.0",
            "gate": "REVIEW_ROUTER",
            "result": PASS,
            "reviewer": reviewer,
            "failed_stage": failed_stage,
            "detailed_reason": "review returned PASS; no rework or stop is required",
            "returned_for_rework": False,
            "target_stage": None,
            "updated_at": updated_at,
            "review_sha256": sha256_obj(review),
        }

    issues = _extract_review_issues(review)
    codes = [x["code"] for x in issues]
    messages = [f"{x['code']}: {x['message']}" for x in issues]
    unknown = [c for c in codes if c not in REWORK_RULES and c not in HARD_STOP_CODES]
    hard_codes = [c for c in codes if c in HARD_STOP_CODES] + unknown

    target_stage: str | None = None
    invalidate_gate: str | None = _stage_gate(failed_stage)
    attempt: int | None = None
    signature: str | None = None
    result = HARD_STOP if hard_codes else REWORK

    if result == REWORK:
        rules = [REWORK_RULES[c] for c in codes]
        rules.sort(key=lambda r: RUN_GATES.index(r[1]))
        target_stage, invalidate_gate = rules[0]
        signature = failed_stage.upper() + "|" + ",".join(sorted(set(codes)))
        counters = state.setdefault("rework_counters", {})
        attempt = int(counters.get(signature, 0)) + 1
        counters[signature] = attempt
        if attempt > max_attempts:
            result = HARD_STOP
            issues.append({
                "code": "REWORK_LIMIT_EXCEEDED",
                "message": f"the same defect was rejected after {max_attempts} automatic rework returns",
            })
            codes.append("REWORK_LIMIT_EXCEEDED")
            messages.append(f"REWORK_LIMIT_EXCEEDED: the same defect was rejected after {max_attempts} automatic rework returns")
            target_stage = None

    marker = REWORK if result == REWORK else HARD_STOP
    invalidated = _invalidate_from(state, invalidate_gate, marker)
    state["workflow_status"] = marker
    state["updated_at"] = updated_at

    if result == REWORK:
        return_note = f"Rejected by {reviewer}; returned to {target_stage} for rework attempt {attempt}/{max_attempts}."
        resume_condition = (
            f"{target_stage} must create a new replacement artifact addressing the listed reasons; "
            "the same reviewer/gate must check it again and return PASS before downstream work resumes."
        )
        user_action_required = False
    else:
        return_note = f"Rejected by {reviewer}; automatic work stopped. No return for rework was issued."
        if "REWORK_LIMIT_EXCEEDED" in codes:
            resume_condition = "User review or catalog/process maintenance is required before this RUN can resume."
        else:
            resume_condition = "The blocking external/configuration/source condition must be corrected, then the failed gate must be rerun in the same RUN."
        user_action_required = bool(set(codes) & USER_ACTION_HARD_STOP_CODES) or bool(unknown) or "REWORK_LIMIT_EXCEEDED" in codes

    decision = {
        "schema_version": "1.0",
        "gate": "REVIEW_ROUTER",
        "result": result,
        "reviewer": reviewer,
        "failed_stage": failed_stage,
        "reason_codes": codes,
        "issues": issues,
        "detailed_reason": "; ".join(messages),
        "returned_for_rework": result == REWORK,
        "return_note": return_note,
        "target_stage": target_stage if result == REWORK else None,
        "rework_attempt": attempt if result == REWORK else None,
        "max_rework_attempts": max_attempts,
        "invalidated_gates": invalidated,
        "resume_condition": resume_condition,
        "user_action_required": user_action_required,
        "review_sha256": sha256_obj(review),
        "updated_at": updated_at,
    }
    if signature:
        decision["defect_signature"] = signature

    history = state.setdefault("review_history", [])
    seq = len(history) + 1
    filename = f"review_decision_{seq:03d}.json"
    decision["artifact"] = filename
    write_json(run_dir / filename, decision)
    decision_hash = sha256_obj(decision)
    history.append({
        "sequence": seq,
        "artifact": filename,
        "sha256": decision_hash,
        "result": result,
        "reviewer": reviewer,
        "failed_stage": failed_stage,
        "reason_codes": codes,
        "target_stage": decision.get("target_stage"),
        "rework_attempt": decision.get("rework_attempt"),
        "invalidated_gates": invalidated,
        "updated_at": updated_at,
    })
    state["last_review_decision"] = {"artifact": filename, "sha256": decision_hash, "result": result}
    state.setdefault("artifacts", {})[filename] = decision_hash
    write_json(state_path, state)
    return decision


def verdict_receipt(state: dict[str, Any]) -> dict[str, Any]:
    workflow_status = str(state.get("workflow_status") or "ACTIVE").upper()
    if workflow_status in {REWORK, HARD_STOP}:
        return {
            "gate": "VERDICT",
            "result": STOP,
            "reason": "WORKFLOW_NOT_READY",
            "workflow_status": workflow_status,
            "last_review_decision": state.get("last_review_decision"),
        }
    gates = state.get("gates") if isinstance(state.get("gates"), dict) else state
    missing = [g for g in REQUIRED_VERDICT_GATES if gates.get(g) != PASS]
    if missing:
        return {"gate": "VERDICT", "result": STOP, "missing_or_failed": missing}
    prealign_report_names=[n for n in state.get("artifacts",{}) if n.startswith("prealign_gate_")]
    if not prealign_report_names:
        return {"gate":"VERDICT","result":STOP,"reason":"PREALIGN_RECEIPT_MISSING"}
    payload = {
        "pipeline_version": VERSION,
        "run_id": state.get("run_id"),
        "manifest_sha256": state.get("manifest_sha256"),
        "gates": {g: gates[g] for g in REQUIRED_VERDICT_GATES},
        "artifacts": state.get("artifacts", {}),
    }
    return {"gate": "VERDICT", "result": PASS, "VERDICT_RECEIPT": sha256_obj(payload), "payload": payload}



def _write_pointer_if_requested(pointer: dict[str, Any], path: str | None) -> None:
    if path:
        write_json(path, pointer)


def cmd_init_run(args: argparse.Namespace) -> int:
    try:
        r = initialize_run(load_json(args.snapshot), args.output_dir, args.run_id, args.created_at)
    except ValueError as e:
        r = {"gate": "RUN_INIT", "result": STOP, "reason": "SNAPSHOT_INVALID", "message": str(e)}
    if r.get("pointer"):
        _write_pointer_if_requested(r["pointer"], args.pointer_output)
    if args.output:
        write_json(args.output, r)
    else:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0 if r.get("result") == PASS else 6


def cmd_sync_run(args: argparse.Namespace) -> int:
    try:
        r = sync_run_inputs(args.run_dir, load_json(args.snapshot), args.updated_at)
    except ValueError as e:
        r = {"gate": "RUN_SYNC", "result": STOP, "reason": "SNAPSHOT_INVALID", "message": str(e)}
    if r.get("pointer"):
        _write_pointer_if_requested(r["pointer"], args.pointer_output)
    if args.output:
        write_json(args.output, r)
    else:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0 if r.get("result") == PASS else 7


def cmd_close_run(args: argparse.Namespace) -> int:
    r = close_run(args.run_dir, args.mode, args.updated_at)
    if r.get("pointer"):
        _write_pointer_if_requested(r["pointer"], args.pointer_output)
    if args.output:
        write_json(args.output, r)
    else:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0 if r.get("result") == PASS else 8


def cmd_binding(args: argparse.Namespace) -> int:
    r = verify_binding(load_json(args.config), args.spec, args.reference)
    write_json(args.output, r) if args.output else print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0 if r["result"] == PASS else 5

def cmd_lint(args: argparse.Namespace) -> int:
    r = lint_geometry_config(load_json(args.config))
    write_json(args.output, r) if args.output else print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0 if r["result"] == PASS else 2


def cmd_geometry(args: argparse.Namespace) -> int:
    cfg=load_json(args.config)
    gate=None
    if all([args.prealign_report,args.prealign_artifact,args.raw,args.reference,args.normalized]):
        art=load_json(args.prealign_artifact)
        report=load_json(args.prealign_report)
        validated=validate_prealign(cfg,art,args.raw,args.reference,args.normalized)
        if report==validated and validated["result"]==PASS:
            gate=validated
    r = validate_geometry_proposal(cfg, load_json(args.proposal), gate)
    write_json(args.output, r) if args.output else print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0 if r["result"] == PASS else 3


def cmd_route_review(args: argparse.Namespace) -> int:
    r = route_review(args.run_dir, load_json(args.review), args.max_attempts, args.updated_at)
    if args.output:
        write_json(args.output, r)
    else:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0 if r.get("result") == PASS else (9 if r.get("result") == REWORK else 10)


def cmd_receipt(args: argparse.Namespace) -> int:
    r = verdict_receipt(load_json(args.state))
    write_json(args.output, r) if args.output else print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0 if r["result"] == PASS else 4


def cmd_hash(args: argparse.Namespace) -> int:
    print(sha256_file(args.file))
    return 0


# PREALIGN 0.8: this is intentionally a separate, auditable geometric stage.
# All points in annotations are observations, not attributed coin features.
def _cv():
    try:
        import cv2
        import numpy as np
    except ImportError as exc:
        raise RuntimeError("PREALIGN requires cv2 and numpy") from exc
    return cv2, np


def _points(value: Any, least: int, name: str) -> list[list[float]]:
    if not isinstance(value, list) or len(value) < least or not all(_is_num_pair(p) for p in value):
        raise ValueError(f"{name}: expected at least {least} finite 2D coordinates")
    return [[float(p[0]), float(p[1])] for p in value]


def _fit_rim(pts: list[list[float]]) -> dict[str, Any]:
    cv2, np = _cv()
    ellipse = cv2.fitEllipse(np.asarray(pts, dtype=np.float32))
    center, dims, angle = ellipse
    if min(dims) < 5:
        raise ValueError("rim ellipse dimensions too small")
    theta = math.radians(angle)
    ct, st = math.cos(theta), math.sin(theta)
    cx, cy = center
    a, b = dims[0]/2., dims[1]/2.
    residuals = []
    for x, y in pts:
        x, y = x-cx, y-cy
        u, v = ct*x+st*y, -st*x+ct*y
        r = math.hypot(u/a, v/b)
        residuals.append(abs(r-1)*max(a,b))
    return {"center":[float(cx),float(cy)],"semiaxes":[float(a),float(b)],
            "axis_angle_degrees":float(angle), "max_rim_residual_px":max(residuals),
            "rms_rim_residual_px":math.sqrt(sum(z*z for z in residuals)/len(residuals))}


def _matrices_from_measurements(annotation: dict[str, Any]) -> tuple[Any, Any, Any, dict[str, Any]]:
    cv2, np = _cv()
    rawrim = _fit_rim(_points(annotation.get("raw_rim_points"), 12, "raw_rim_points"))
    refrim = _fit_rim(_points(annotation.get("reference_rim_points"), 12, "reference_rim_points"))
    ra,rb = rawrim["semiaxes"]
    refa,refb = refrim["semiaxes"]
    # Reference size uses the actual canonical outer coin radius, not a guessed value.
    radius = (refa+refb)/2.
    angle = math.radians(rawrim["axis_angle_degrees"])
    ca,sa = math.cos(angle),math.sin(angle)
    rotation = np.array([[ca,-sa],[sa,ca]], dtype=np.float64)
    correction = rotation @ np.diag([radius/ra,radius/rb]) @ rotation.T
    C = np.eye(3,dtype=np.float64)
    C[:2,:2]=correction
    C[:2,2]=np.array(refrim["center"])-correction @ np.array(rawrim["center"])
    controls=annotation.get("orientation_controls")
    if not isinstance(controls,list) or len(controls)<2:
        raise ValueError("orientation_controls requires at least two nondiagnostic control landmarks")
    src,dst=[],[]
    for item in controls:
        if not isinstance(item,dict) or item.get("role")!="COMMON_NONDIAGNOSTIC_CONTOUR":
            raise ValueError("orientation_controls must be explicitly nondiagnostic")
        src.extend(_points([item.get("raw")],1,"orientation control raw"))
        dst.extend(_points([item.get("reference")],1,"orientation control reference"))
    X=np.array([((C @ np.array([*p,1.]))[:2]) for p in src])
    Y=np.array(dst)
    if np.linalg.norm(X[0]-X[1])<5 or np.linalg.norm(Y[0]-Y[1])<5:
        raise ValueError("orientation control landmarks are degenerate")
    # Rigid fit: no scale/shear or perspective may be smuggled into orient_matrix.
    xm=X.mean(axis=0); ym=Y.mean(axis=0)
    H=(X-xm).T @ (Y-ym)
    U,S,Vt=np.linalg.svd(H)
    R=Vt.T @ np.diag([1.,np.linalg.det(Vt.T@U.T)]) @ U.T
    O=np.eye(3,dtype=np.float64)
    O[:2,:2]=R
    O[:2,2]=ym-R @ xm
    total=O@C
    return C,O,total,{"raw_rim_fit":rawrim,"reference_rim_fit":refrim}


def _warp_image(raw_path: str|Path, matrix: Any, size: list[int]):
    cv2,np=_cv()
    im=cv2.imread(str(raw_path),cv2.IMREAD_UNCHANGED)
    if im is None: raise ValueError("raw image unreadable")
    return cv2.warpAffine(im,matrix[:2,:],(int(size[0]),int(size[1])),
                          flags=cv2.INTER_LINEAR,borderMode=cv2.BORDER_CONSTANT,borderValue=(0,0,0))


def create_prealign(config: dict[str,Any], ann: dict[str,Any], raw_path: str|Path,
                    ref_path: str|Path, normalized_path: str|Path) -> dict[str,Any]:
    cv2,np=_cv()
    if sha256_file(ref_path)!=config.get("reference_sha256"):
        raise ValueError("REFERENCE_HASH_MISMATCH")
    if ann.get("reference_file_id")!=config.get("reference_file_id"):
        raise ValueError("reference file ID differs from canonical config")
    if not isinstance(ann.get("input_file_id"),str) or not ann["input_file_id"] or ann["input_file_id"].startswith("TBD"):
        raise ValueError("actual Drive input_file_id is required")
    if ann.get("annotation_status")!="GEOMETER_CONFIRMED":
        raise ValueError("GEOMETER must confirm physical rim and nondiagnostic landmarks before the machine gate")
    C,O,T,fits=_matrices_from_measurements(ann)
    inv=np.linalg.inv(T)
    canvas=config.get("canvas")
    if not isinstance(canvas,list) or len(canvas)!=2 or any(not isinstance(x,int) or x<=0 for x in canvas):
        raise ValueError("CONFIG_INVALID canvas")
    normalized_path=Path(normalized_path)
    normalized_path.parent.mkdir(parents=True,exist_ok=True)
    image=_warp_image(raw_path,T,canvas)
    if not cv2.imwrite(str(normalized_path),image,[cv2.IMWRITE_PNG_COMPRESSION,3]):
        raise ValueError("could not write normalized image")
    return {"schema_version":"1.0", "algorithm":"NUM4_PREALIGN_0.8",
            "input_file_id":ann["input_file_id"],"annotation_status":ann["annotation_status"],
            "raw_sha256":sha256_file(raw_path),
            "reference_file_id":ann["reference_file_id"],"reference_sha256":sha256_file(ref_path),
            "raw_rim_points":ann["raw_rim_points"],"reference_rim_points":ann["reference_rim_points"],
            "orientation_controls":ann["orientation_controls"],
            "orientation_validation":ann.get("orientation_validation",[]),
            "raw_rim_fit":fits["raw_rim_fit"],"reference_rim_fit":fits["reference_rim_fit"],
            "shape_matrix":C.tolist(),"orientation_matrix":O.tolist(),
            "raw_to_normalized":T.tolist(),"normalized_to_raw":inv.tolist(),
            "correction_model":"ELLIPSE_TO_CIRCLE_FROM_RIM_ONLY",
            "canvas":canvas,"normalized_sha256":sha256_file(normalized_path),
            "post_transforms":[],"prealign_provenance":"RIM_AND_COMMON_NONDIAGNOSTIC_CONTOURS_ONLY"}


def validate_prealign(config: dict[str,Any], artifact: dict[str,Any], raw_path: str|Path,
                      ref_path: str|Path, normalized_path: str|Path) -> dict[str,Any]:
    issues=[]
    def fail(code:str,message:str,**extra):issues.append({"code":code,"message":message,**extra})
    if lint_geometry_config(config).get("result")!=PASS:
        return {"gate":"PREALIGN","result":STOP,"issues":[{"code":"CONFIG_NOT_PASS","message":"canonical geometry config not PASS"}]}
    for key,path in [("raw_sha256",raw_path),("reference_sha256",ref_path),("normalized_sha256",normalized_path)]:
        try: actual=sha256_file(path)
        except OSError:actual=None
        if artifact.get(key)!=actual or actual is None:
            fail("PREALIGN_HASH_MISMATCH",f"{key}: actual bytes do not match recorded hash")
    if artifact.get("reference_file_id") !=config.get("reference_file_id") or artifact.get("reference_sha256")!=config.get("reference_sha256"):
        fail("REFERENCE_HASH_MISMATCH","prealign does not refer to canonical full reference")
    if not artifact.get("input_file_id") or str(artifact.get("input_file_id")).startswith("TBD") or artifact.get("algorithm")!="NUM4_PREALIGN_0.8" or artifact.get("annotation_status")!="GEOMETER_CONFIRMED":
        fail("PREALIGN_PROVENANCE_INVALID","missing input ID or unsupported algorithm")
    if artifact.get("post_transforms") not in ([],None) or artifact.get("prealign_provenance")!="RIM_AND_COMMON_NONDIAGNOSTIC_CONTOURS_ONLY":
        fail("PREALIGN_PROVENANCE_INVALID","forbidden post correction or invalid provenance")
    try:
        cv2,np=_cv()
        C,O,T,fits=_matrices_from_measurements(artifact)
        serialized=np.asarray(artifact["raw_to_normalized"],dtype=float)
        backward=np.asarray(artifact["normalized_to_raw"],dtype=float)
        shape=np.asarray(artifact["shape_matrix"],dtype=float)
        orient=np.asarray(artifact["orientation_matrix"],dtype=float)
        for m in (serialized,backward,shape,orient):
            if m.shape!=(3,3) or not np.isfinite(m).all() or max(abs(m[2]-[0,0,1]))>1e-9:
                raise ValueError("invalid or nonfinite 3x3 affine matrix")
        if np.max(abs(serialized-T))>1e-5 or np.max(abs(orient@shape-T))>1e-5 or np.max(abs(backward@serialized-np.eye(3)))>1e-5:
            fail("PREALIGN_MATRIX_MISMATCH","recorded forward/inverse matrices do not reproduce edge/landmark-derived transform")
        if abs(np.linalg.det(orient[:2,:2])-1)>1e-5 or np.max(abs(orient[:2,:2].T@orient[:2,:2]-np.eye(2)))>1e-5:
            fail("PREALIGN_MODEL_INVALID","orient matrix must be rigid (rotation/translation only)")
        if artifact.get("canvas")!=config.get("canvas"):
            fail("PREALIGN_CANVAS_MISMATCH","output canvas differs from canonical full reference")
        if artifact.get("correction_model")!="ELLIPSE_TO_CIRCLE_FROM_RIM_ONLY":
            fail("PREALIGN_MODEL_INVALID","correction is not edge-derived ellipse-to-circle")
        rawimg=cv2.imread(str(raw_path),cv2.IMREAD_UNCHANGED)
        refimg=cv2.imread(str(ref_path),cv2.IMREAD_UNCHANGED)
        actualimg=cv2.imread(str(normalized_path),cv2.IMREAD_UNCHANGED)
        if any(x is None for x in (rawimg,refimg,actualimg)):
            raise ValueError("one of the required images is unreadable")
        if (refimg.shape[1],refimg.shape[0])!=tuple(config["canvas"]):
            fail("REFERENCE_CANVAS_MISMATCH","reference image dimensions differ from bound canvas")
        if actualimg.shape[:2]!=(config["canvas"][1],config["canvas"][0]):
            fail("PREALIGN_CANVAS_MISMATCH","normalized image dimensions invalid")
        else:
            expected=_warp_image(raw_path,T,config["canvas"])
            if expected.shape!=actualimg.shape or not np.array_equal(expected,actualimg):
                fail("PREALIGN_IMAGE_MISMATCH","normalized pixels are not the result of the declared single global transformation")
        # Approved existing reference tolerances are used, not new invented thresholds.
        edge_limit=float(config["max_control_residual_px"])
        validation_limit=float(config["max_validation_residual_px"])
        rawfit=fits["raw_rim_fit"]; reffit=fits["reference_rim_fit"]
        if reffit["max_rim_residual_px"]>edge_limit:
            fail("PREALIGN_RIM_RESIDUAL","reference rim points do not form approved circle",observed=reffit["max_rim_residual_px"],threshold=edge_limit,unit="px")
        ref_axis_err=abs(reffit["semiaxes"][0]-reffit["semiaxes"][1])
        if ref_axis_err>edge_limit:
            fail("PREALIGN_REFERENCE_NOT_CIRCULAR","reference outer rim is not circular",observed=ref_axis_err,threshold=edge_limit,unit="px")
        p=np.array([*rawfit["center"],1.]); radius=sum(reffit["semiaxes"])/2
        rim=np.asarray(_points(artifact.get("raw_rim_points"),12,"raw rim"),dtype=float)
        roundrim=np.array([((shape @ np.array([*pt,1.]))[:2]) for pt in rim])
        err=np.max(abs(np.linalg.norm(roundrim-np.array(reffit["center"]),axis=1)-radius))
        if err>edge_limit:
            fail("PREALIGN_ROUNDNESS","edge correction did not circularize raw rim",observed=float(err),threshold=edge_limit,unit="px")
        # Check rim witnesses actually lie on a strong image boundary, not arbitrary coordinates.
        for label,img,pts in [("raw",rawimg,artifact.get("raw_rim_points")),("reference",refimg,artifact.get("reference_rim_points"))]:
            grey=cv2.cvtColor(img,cv2.COLOR_BGR2GRAY) if len(img.shape)==3 else img
            g=cv2.magnitude(cv2.Sobel(grey,cv2.CV_32F,1,0),cv2.Sobel(grey,cv2.CV_32F,0,1))
            cutoff=float(np.quantile(g,0.65))
            witnessed=0
            for x,y in pts:
                u,v=int(round(x)),int(round(y))
                if not (2<=u<grey.shape[1]-2 and 2<=v<grey.shape[0]-2):continue
                if g[v-2:v+3,u-2:u+3].max()>cutoff:witnessed+=1
            if witnessed<len(pts)*0.75:
                fail("PREALIGN_RIM_NOT_EVIDENCED",f"{label} rim annotations do not coincide with image edges",observed=witnessed,threshold=math.ceil(len(pts)*0.75),unit="points")
        # Nondiagnostic landmarks and held-out checks must not touch approved diagnostic mask.
        mask=np.zeros(config["canvas"][1]*config["canvas"][0],dtype=np.uint8)
        for z in config["zones"]:
            for start,length in z["diagnostic_region"]["runs"]:mask[start:start+length]=1
        for key,limit in [("orientation_controls",validation_limit),("orientation_validation",validation_limit)]:
            landmark_list=artifact.get(key)
            if not isinstance(landmark_list,list) or (key=="orientation_validation" and len(landmark_list)<2):
                fail("PREALIGN_LANDMARKS_MISSING",f"{key} requires independent nondiagnostic landmarks")
                continue
            errs=[]
            for mark in landmark_list:
                if not isinstance(mark,dict) or mark.get("role")!="COMMON_NONDIAGNOSTIC_CONTOUR":
                    fail("PREALIGN_LANDMARKS_INVALID",f"{key}: common-nondiagnostic-contour provenance required");continue
                try:
                    rawpoint=_points([mark["raw"]],1,"raw point")[0]
                    refpoint=_points([mark["reference"]],1,"ref point")[0]
                except (KeyError,ValueError) as exc:
                    fail("PREALIGN_LANDMARKS_INVALID",str(exc));continue
                ix,iy=round(refpoint[0]),round(refpoint[1])
                if not 0<=ix<config["canvas"][0] or not 0<=iy<config["canvas"][1]:
                    fail("PREALIGN_LANDMARKS_INVALID","reference landmark outside full canvas");continue
                if mask[iy*config["canvas"][0]+ix]:
                    fail("PREALIGN_DIAGNOSTIC_LEAKAGE","prealign landmark overlaps approved diagnostic region")
                trans=(T@np.array([*rawpoint,1]))[:2]
                errs.append(float(np.linalg.norm(trans-np.array(refpoint))))
            if errs and max(errs)>limit:
                fail("PREALIGN_LANDMARK_RESIDUAL",f"{key} alignment residual above approved validation limit",observed=max(errs),threshold=limit,unit="px")
        # Zero distortion beyond the single edge-correction + rigid orientation.
    except (ValueError,KeyError,IndexError,TypeError,OverflowError,cv2.error) as exc:
        fail("PREALIGN_INVALID",str(exc))
    payload={"gate":"PREALIGN","result":PASS if not issues else STOP,
             "issues":issues,"config_sha256":sha256_obj(config),"prealign_sha256":sha256_obj(artifact),
             "raw_sha256":artifact.get("raw_sha256"),"normalized_sha256":artifact.get("normalized_sha256"),
             "reference_file_id":artifact.get("reference_file_id"),"input_file_id":artifact.get("input_file_id")}
    if not issues:payload["prealign_receipt"]=sha256_obj(payload)
    return payload


def commit_prealign(run_dir:str|Path, validated:dict[str,Any], artifact:dict[str,Any],
                    normalized_path:str|Path, raw_path:str|Path,ref_path:str|Path,config:dict[str,Any])->dict[str,Any]:
    # Never trust a supplied PASS JSON without independently rerunning machine validation.
    again=validate_prealign(config,artifact,raw_path,ref_path,normalized_path)
    if again.get("result")!=PASS or again!=validated:
        return {"gate":"PREALIGN_COMMIT","result":STOP,"reason":"PREALIGN_NOT_VERIFIED","review":again}
    run_dir=Path(run_dir)
    statepath=run_dir/"run_state.json"
    state=load_json(statepath)
    if state.get("status")!="ACTIVE" or state.get("workflow_status")==HARD_STOP:
        return {"gate":"PREALIGN_COMMIT","result":STOP,"reason":"RUN_NOT_ACTIVE"}
    if state.get("gates",{}).get("SOURCES_PASS")!=PASS or state["gates"].get("BRANCH_PASS")!=PASS:
        return {"gate":"PREALIGN_COMMIT","result":STOP,"reason":"PREREQUISITE_NOT_PASS"}
    # Update only this gate; preserve existing review history, signature counters and a geometry REWORK marker.
    manifest_path=run_dir/"manifest.json"
    if not manifest_path.exists():
        return {"gate":"PREALIGN_COMMIT","result":STOP,"reason":"RUN_FILES_MISSING"}
    manifest=load_json(manifest_path)
    if manifest.get("run_id")!=state.get("run_id") or sha256_obj(manifest)!=state.get("manifest_sha256"):
        return {"gate":"PREALIGN_COMMIT","result":STOP,"reason":"RUN_MANIFEST_MISMATCH"}
    refs=sorted(set(str(value) for key,value in manifest.get("canonical_sources",{}).items()
                    if key.endswith("_reference_id") and isinstance(value,str) and value))
    if not refs:
        return {"gate":"PREALIGN_COMMIT","result":STOP,"reason":"CANONICAL_REFERENCES_NOT_BOUND"}
    if artifact['reference_file_id'] not in refs:
        return {"gate":"PREALIGN_COMMIT","result":STOP,"reason":"REFERENCE_NOT_IN_ACTIVE_BRANCH"}
    state["VERDICT_RECEIPT"]=None
    state["updated_at"]=utc_now_iso()
    filename=f"prealign_{artifact['reference_file_id']}.json"
    reportname=f"prealign_gate_{artifact['reference_file_id']}.json"
    write_json(run_dir/filename,artifact)
    write_json(run_dir/reportname,validated)
    state.setdefault("artifacts",{})[filename]=sha256_obj(artifact)
    state["artifacts"][reportname]=sha256_obj(validated)
    # Only all active canonical references can satisfy this aggregate gate.
    passed=[]
    for ref in refs:
        artfile=run_dir/f"prealign_{ref}.json"
        reportfile=run_dir/f"prealign_gate_{ref}.json"
        if artfile.is_file() and reportfile.is_file():
            a=load_json(artfile);r=load_json(reportfile)
            if r.get("result")==PASS and r.get("prealign_receipt") and r.get("reference_file_id")==ref \
                and r.get("prealign_sha256")==sha256_obj(a) \
                and state["artifacts"].get(artfile.name)==sha256_obj(a) \
                and state["artifacts"].get(reportfile.name)==sha256_obj(r):
                passed.append(ref)
    state["gates"]["PREALIGN_PASS"]=PASS if len(passed)==len(refs) else "PENDING"
    for g in ("GEOMETRY_PASS","DIAGNOSTICS_PASS","ALTERNATIVES_PASS","AUDIT_PASS"):
        if state["gates"].get(g)==PASS:state["gates"][g]="PENDING"
    write_json(statepath,state)
    return {"gate":"PREALIGN_COMMIT","result":PASS,"artifact":filename,"receipt":validated["prealign_receipt"],
            "aggregate_gate":state["gates"]["PREALIGN_PASS"],"completed_references":passed,"required_references":refs}


def cmd_build_prealign(args:argparse.Namespace)->int:
    try:
        cfg=load_json(args.config)
        ann=load_json(args.annotations)
        r=create_prealign(cfg,ann,args.raw,args.reference,args.normalized)
        write_json(args.artifact,r)
        result=validate_prealign(cfg,r,args.raw,args.reference,args.normalized)
        if args.report:write_json(args.report,result)
        else:print(json.dumps(result,ensure_ascii=False,indent=2))
    except (ValueError,RuntimeError,OSError) as exc:
        result={"gate":"PREALIGN","result":STOP,"issues":[{"code":"PREALIGN_INVALID","message":str(exc)}]}
        if args.report:write_json(args.report,result)
        else:print(json.dumps(result,ensure_ascii=False,indent=2))
    return 0 if result["result"]==PASS else 6


def cmd_validate_prealign(args:argparse.Namespace)->int:
    result=validate_prealign(load_json(args.config),load_json(args.artifact),args.raw,args.reference,args.normalized)
    if args.output:write_json(args.output,result)
    else:print(json.dumps(result,ensure_ascii=False,indent=2))
    return 0 if result["result"]==PASS else 6


def cmd_commit_prealign(args:argparse.Namespace)->int:
    r=commit_prealign(args.run_dir,load_json(args.report),load_json(args.artifact),args.normalized,args.raw,args.reference,load_json(args.config))
    if args.output:write_json(args.output,r)
    else:print(json.dumps(r,ensure_ascii=False,indent=2))
    return 0 if r["result"]==PASS else 6



def propose_prealign_annotations(config:dict[str,Any], raw_file:str|Path, reference_file:str|Path)->dict[str,Any]:
    """Computer-vision proposals only. Never constitutes a PREALIGN_PASS or C1-C3 match."""
    cv2,np=_cv()
    if sha256_file(reference_file)!=config.get("reference_sha256"):
        raise ValueError("REFERENCE_HASH_MISMATCH")
    raw=cv2.imread(str(raw_file));reference=cv2.imread(str(reference_file))
    if raw is None or reference is None:raise ValueError("missing or unreadable photograph")
    def rim_points(image):
        hh,ww=image.shape[:2]
        down=min(1.,850./max(hh,ww))
        im=cv2.resize(image,(round(ww*down),round(hh*down)))
        border=np.concatenate([im[:3,:,:].reshape(-1,3),im[-3:,:,:].reshape(-1,3),
                               im[:,:3,:].reshape(-1,3),im[:,-3:,:].reshape(-1,3)])
        bg=np.median(border,axis=0)
        dist=np.linalg.norm(im.astype(np.float32)-bg,axis=2)
        dist=np.uint8(np.clip(dist,0,255))
        _,binary=cv2.threshold(dist,0,255,cv2.THRESH_BINARY+cv2.THRESH_OTSU)
        binary=cv2.morphologyEx(binary,cv2.MORPH_CLOSE,np.ones((9,9),np.uint8))
        conts,_=cv2.findContours(binary,cv2.RETR_EXTERNAL,cv2.CHAIN_APPROX_NONE)
        conts=[c for c in conts if cv2.contourArea(c)>im.shape[0]*im.shape[1]*.22 and len(c)>100]
        if not conts:raise ValueError("no unambiguous major coin contour detected")
        contour=max(conts,key=cv2.contourArea)[:,0,:].astype(float)/down
        center=contour.mean(axis=0)
        azimuth=np.arctan2(contour[:,1]-center[1],contour[:,0]-center[0])
        angles=np.linspace(-math.pi,math.pi,64,endpoint=False)
        selection=[contour[int(np.argmin(np.abs(np.angle(np.exp(1j*(azimuth-theta))))))].tolist() for theta in angles]
        return selection
    raw_rim=rim_points(raw);ref_rim=rim_points(reference)
    guess={"raw_rim_points":raw_rim,"reference_rim_points":ref_rim,"orientation_controls":[],"orientation_validation":[]}
    C,_,_,_= _matrices_from_measurements({**guess,"orientation_controls":[
        {"raw":[100,100],"reference":[100,100],"role":"COMMON_NONDIAGNOSTIC_CONTOUR"},
        {"raw":[200,200],"reference":[200,200],"role":"COMMON_NONDIAGNOSTIC_CONTOUR"}]})
    shaped=_warp_image(raw_file,C,config["canvas"])
    w,h=config["canvas"]
    exclusion=np.zeros((h,w),dtype=np.uint8)
    for z in config["zones"]:
        for start,length in z["diagnostic_region"]["runs"]:exclusion.ravel()[start:start+length]=255
    # Explicitly exclude all approved diagnostic evidence, including its boundary buffer.
    exclusion=cv2.dilate(exclusion,np.ones((31,31),np.uint8))
    mask=255-exclusion
    sift=cv2.SIFT_create(nfeatures=2500)
    kp1,d1=sift.detectAndCompute(cv2.cvtColor(shaped,cv2.COLOR_BGR2GRAY),mask)
    kp2,d2=sift.detectAndCompute(cv2.cvtColor(reference,cv2.COLOR_BGR2GRAY),mask)
    if d1 is None or d2 is None or len(d1)<10 or len(d2)<10:
        raise ValueError("insufficient common nondiagnostic details for orienting")
    matcher=cv2.BFMatcher(cv2.NORM_L2)
    pairs=matcher.knnMatch(d1,d2,k=2)
    good=[m for m,n in pairs if m.distance<.69*n.distance]
    if len(good)<10:raise ValueError("insufficient confident common nondiagnostic correspondences")
    src=np.float32([kp1[m.queryIdx].pt for m in good]);dst=np.float32([kp2[m.trainIdx].pt for m in good])
    model,inlier=cv2.estimateAffinePartial2D(src,dst,method=cv2.RANSAC,ransacReprojThreshold=4.)
    if model is None or inlier is None:raise ValueError("orientation has no consistent rigid hypothesis")
    ix=np.flatnonzero(inlier.ravel()>0)
    if len(ix)<8:raise ValueError("too few independently consistent orientation landmarks")
    inv=np.linalg.inv(C)
    candidates=[]
    for i in ix:
        m=good[i]
        p=np.array([*src[i],1.])
        rawpoint=(inv@p)[:2]
        q=dst[i]
        if min(q[0],q[1],w-q[0],h-q[1])<10:continue
        candidates.append((float(m.distance),{"raw":list(map(float,rawpoint)),
                          "reference":[float(q[0]),float(q[1])],
                          "role":"COMMON_NONDIAGNOSTIC_CONTOUR",
                          "description":"SIFT suggested common contour, verify physical correspondence"}))
    candidates.sort(key=lambda x:x[0])
    accepted=[]
    for _,cand in candidates:
        q=np.array(cand["reference"])
        if all(np.linalg.norm(q-np.array(prev["reference"]))>=35. for prev in accepted):
            accepted.append(cand)
        if len(accepted)>=12:break
    if len(accepted)<6:raise ValueError("not enough spatially independent contour matches")
    return {"schema_version":"1.0","input_file_id":"TBD_DRIVE_INPUT_FILE_ID",
            "reference_file_id":config["reference_file_id"],
            "raw_rim_points":raw_rim,"reference_rim_points":ref_rim,
            "orientation_controls":accepted[:3],"orientation_validation":accepted[3:],
            "annotation_status":"CV_SUGGESTION_REQUIRES_GEOMETER_VERIFICATION",
            "note":"Do not treat suggested correspondences as C1-C3 or as confirmed until visually checked."}


def cmd_suggest_prealign(args:argparse.Namespace)->int:
    try:
        proposal=propose_prealign_annotations(load_json(args.config),args.raw,args.reference)
        write_json(args.output,proposal) if args.output else print(json.dumps(proposal,ensure_ascii=False,indent=2))
        return 0
    except (ValueError,RuntimeError) as e:
        obj={"gate":"PREALIGN_SUGGESTION","result":STOP,"reason":"INSUFFICIENT_UNBIASED_ALIGNMENT_EVIDENCE","detail":str(e)}
        write_json(args.output,obj) if args.output else print(json.dumps(obj,ensure_ascii=False,indent=2))
        return 6


def migrate_run_prealign(run_dir: str | Path) -> dict[str, Any]:
    """Upgrade old active RUN fail-closed, without clearing old failures or counters."""
    path=Path(run_dir)/"run_state.json"
    if not path.is_file():return {"gate":"RUN_PREALIGN_MIGRATE","result":STOP,"reason":"RUN_FILES_MISSING"}
    state=load_json(path)
    if state.get("status")!="ACTIVE":return {"gate":"RUN_PREALIGN_MIGRATE","result":STOP,"reason":"RUN_NOT_ACTIVE"}
    gates=state.setdefault("gates",{})
    if "PREALIGN_PASS" in gates:
        return {"gate":"RUN_PREALIGN_MIGRATE","result":PASS,"changed":False,"workflow_status":state.get("workflow_status")}
    gates["PREALIGN_PASS"]="PENDING"
    # Historical geometry and reviews remain unchanged, but no existing downstream PASS
    # may be reused until the new mandatory prerequisite is satisfied.
    for downstream in ("GEOMETRY_PASS","DIAGNOSTICS_PASS","ALTERNATIVES_PASS","AUDIT_PASS"):
        if gates.get(downstream)==PASS:gates[downstream]="PENDING"
    state["VERDICT_RECEIPT"]=None
    state["updated_at"]=utc_now_iso()
    state["prealign_migration"]={"pipeline_version":VERSION,"preserved_review_history":len(state.get("review_history",[])),
                                "preserved_rework_counters":True,"old_verdict_invalidated":True}
    write_json(path,state)
    return {"gate":"RUN_PREALIGN_MIGRATE","result":PASS,"changed":True,"workflow_status":state.get("workflow_status"),
            "prealign_status":"PENDING","history_count":len(state.get("review_history",[]))}


def cmd_migrate_run(args: argparse.Namespace)->int:
    result=migrate_run_prealign(args.run_dir)
    if args.output:write_json(args.output,result)
    else:print(json.dumps(result,ensure_ascii=False,indent=2))
    return 0 if result.get("result")==PASS else 5


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="num_pipeline.py")
    p.add_argument("--version", action="version", version=VERSION)
    sp = p.add_subparsers(dest="cmd", required=True)

    q = sp.add_parser("migrate-run-prealign")
    q.add_argument("run_dir");q.add_argument("--output")
    q.set_defaults(func=cmd_migrate_run)

    q = sp.add_parser("init-run")
    q.add_argument("snapshot")
    q.add_argument("output_dir")
    q.add_argument("--run-id")
    q.add_argument("--created-at")
    q.add_argument("--pointer-output")
    q.add_argument("--output")
    q.set_defaults(func=cmd_init_run)

    q = sp.add_parser("sync-run-inputs")
    q.add_argument("run_dir")
    q.add_argument("snapshot")
    q.add_argument("--updated-at")
    q.add_argument("--pointer-output")
    q.add_argument("--output")
    q.set_defaults(func=cmd_sync_run)

    q = sp.add_parser("close-run")
    q.add_argument("run_dir")
    q.add_argument("--mode", choices=["VERDICT", "ABORT"], required=True)
    q.add_argument("--updated-at")
    q.add_argument("--pointer-output")
    q.add_argument("--output")
    q.set_defaults(func=cmd_close_run)

    q = sp.add_parser("verify-binding")
    q.add_argument("config")
    q.add_argument("spec")
    q.add_argument("reference")
    q.add_argument("--output")
    q.set_defaults(func=cmd_binding)

    q = sp.add_parser("lint-geometry-config")
    q.add_argument("config")
    q.add_argument("--output")
    q.set_defaults(func=cmd_lint)

    q = sp.add_parser("validate-geometry")
    q.add_argument("config")
    q.add_argument("proposal")
    q.add_argument("--prealign-report")
    q.add_argument("--prealign-artifact")
    q.add_argument("--raw")
    q.add_argument("--reference")
    q.add_argument("--normalized")
    q.add_argument("--output")
    q.set_defaults(func=cmd_geometry)

    q = sp.add_parser("suggest-prealign")
    q.add_argument("config");q.add_argument("raw");q.add_argument("reference");q.add_argument("--output")
    q.set_defaults(func=cmd_suggest_prealign)
    q = sp.add_parser("build-prealign")
    q.add_argument("config");q.add_argument("annotations");q.add_argument("raw");q.add_argument("reference")
    q.add_argument("normalized");q.add_argument("artifact");q.add_argument("--report")
    q.set_defaults(func=cmd_build_prealign)
    q = sp.add_parser("validate-prealign")
    q.add_argument("config");q.add_argument("artifact");q.add_argument("raw");q.add_argument("reference");q.add_argument("normalized")
    q.add_argument("--output");q.set_defaults(func=cmd_validate_prealign)
    q = sp.add_parser("commit-prealign")
    q.add_argument("run_dir");q.add_argument("config");q.add_argument("artifact");q.add_argument("report")
    q.add_argument("raw");q.add_argument("reference");q.add_argument("normalized")
    q.add_argument("--output");q.set_defaults(func=cmd_commit_prealign)

    q = sp.add_parser("route-review")
    q.add_argument("run_dir")
    q.add_argument("review")
    q.add_argument("--max-attempts", type=int)
    q.add_argument("--updated-at")
    q.add_argument("--output")
    q.set_defaults(func=cmd_route_review)

    q = sp.add_parser("verdict-receipt")
    q.add_argument("state")
    q.add_argument("--output")
    q.set_defaults(func=cmd_receipt)

    q = sp.add_parser("sha256")
    q.add_argument("file")
    q.set_defaults(func=cmd_hash)
    return p


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())