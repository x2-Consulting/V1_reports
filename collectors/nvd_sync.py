"""
NVD CVE local cache sync.

Full sync: downloads all ~260k CVEs from NVD API v2.0 (paged, 2000/page).
Incremental sync: downloads only CVEs modified in the last N days.

Stores results in the cve_cache table. Existing rows are upserted.

Sync status is tracked via AppSetting keys:
  nvd_sync_status          : "idle" | "syncing_full" | "syncing_incremental" | "failed"
  nvd_last_full_sync       : ISO datetime of last successful full sync
  nvd_last_incremental_sync: ISO datetime of last successful incremental sync
  nvd_total_cached         : integer string
  nvd_sync_progress        : "N / TOTAL" during sync
  nvd_sync_error           : last error message
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

# Make web/ importable when run as a standalone script or from the collectors package
_web_dir = str(Path(__file__).resolve().parent.parent / "web")
if _web_dir not in sys.path:
    sys.path.insert(0, _web_dir)

from database import SessionLocal  # noqa: E402  (after sys.path patch)
from models import AppSetting, CVECache  # noqa: E402

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE_SIZE = 2000
_SLEEP_BETWEEN_PAGES = 0.7  # seconds — stays safely under 50 req/30 s


# ── Internal helpers ──────────────────────────────────────────────────────────

def _set_status(db, key: str, value: str) -> None:
    """Upsert an AppSetting row directly (no encryption, no circular import)."""
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    now = datetime.utcnow()  # naive UTC — MariaDB DATETIME has no tz
    if row:
        row.value = value
        row.updated_at = now
    else:
        row = AppSetting(
            key=key,
            value=value,
            is_encrypted=False,
            description="",
            updated_at=now,
        )
        db.add(row)
    db.commit()


def _count_cached(db) -> int:
    return db.query(CVECache).count()


def _upsert_cve(db, cve_id: str, parsed: dict) -> None:
    """Insert or update a single CVE row."""
    refs = parsed.get("all_refs", [])
    refs_json = json.dumps(refs)

    row = db.query(CVECache).filter(CVECache.cve_id == cve_id).first()
    now = datetime.utcnow()  # naive UTC — MariaDB DATETIME has no tz
    if row:
        row.description = parsed.get("description", "")
        row.cvss_score = parsed.get("cvss", None)
        row.cvss_severity = parsed.get("severity", None)
        row.cvss_vector = parsed.get("cvss_vector", None)
        row.cwe = parsed.get("cwe", None)
        row.patch_url = parsed.get("patch_url", None)
        row.refs_json = refs_json
        row.published = parsed.get("published", None)
        row.modified = parsed.get("modified", None)
        row.nvd_status = parsed.get("status", None)
        row.cached_at = now
    else:
        row = CVECache(
            cve_id=cve_id,
            description=parsed.get("description", ""),
            cvss_score=parsed.get("cvss", None),
            cvss_severity=parsed.get("severity", None),
            cvss_vector=parsed.get("cvss_vector", None),
            cwe=parsed.get("cwe", None),
            patch_url=parsed.get("patch_url", None),
            refs_json=refs_json,
            published=parsed.get("published", None),
            modified=parsed.get("modified", None),
            nvd_status=parsed.get("status", None),
            cached_at=now,
        )
        db.add(row)


def _fetch_page(api_key: str | None, params: dict) -> dict:
    """Fetch one page from NVD API, retrying once on 403/429."""
    headers = {"apiKey": api_key} if api_key else {}
    for attempt in range(2):
        resp = httpx.get(NVD_BASE, params=params, headers=headers, timeout=30)
        if resp.status_code in (403, 429):
            time.sleep(35)
            continue
        resp.raise_for_status()
        return resp.json()
    resp.raise_for_status()
    return {}


def _sync_pages(api_key: str | None, extra_params: dict, sync_status_key: str) -> None:
    """
    Core paging loop shared by full and incremental sync.
    Runs in a *new* DB session (called from a background thread).
    """
    # Import the parser from the sibling module (same package)
    from collectors.nvd import _parse_nvd_cve

    db = SessionLocal()
    try:
        _set_status(db, "nvd_sync_status", sync_status_key)
        _set_status(db, "nvd_sync_progress", "0 / ?")
        _set_status(db, "nvd_sync_error", "")

        start_index = 0
        total_results = None
        processed = 0
        batch_count = 0

        while True:
            params = {
                "startIndex": start_index,
                "resultsPerPage": _PAGE_SIZE,
                **extra_params,
            }

            try:
                data = _fetch_page(api_key, params)
            except Exception as exc:
                _set_status(db, "nvd_sync_status", "failed")
                _set_status(db, "nvd_sync_error", str(exc))
                raise

            if total_results is None:
                total_results = data.get("totalResults", 0)

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for item in vulns:
                cve_obj = item.get("cve", {})
                cve_id = cve_obj.get("id", "")
                if not cve_id:
                    continue
                parsed = _parse_nvd_cve(cve_obj)
                _upsert_cve(db, cve_id, parsed)
                processed += 1
                batch_count += 1

                if batch_count >= 500:
                    db.commit()
                    batch_count = 0
                    _set_status(
                        db, "nvd_sync_progress",
                        f"{processed:,} / {total_results:,}" if total_results else str(processed),
                    )

            # Commit any remainder for this page
            if batch_count > 0:
                db.commit()
                batch_count = 0

            _set_status(
                db, "nvd_sync_progress",
                f"{processed:,} / {total_results:,}" if total_results else str(processed),
            )

            start_index += len(vulns)
            if total_results is not None and start_index >= total_results:
                break

            time.sleep(_SLEEP_BETWEEN_PAGES)

        # Finalize
        total_cached = _count_cached(db)
        _set_status(db, "nvd_total_cached", str(total_cached))
        _set_status(db, "nvd_sync_status", "idle")
        _set_status(db, "nvd_sync_progress", f"{processed:,} / {total_results:,}" if total_results else str(processed))

        now_iso = datetime.utcnow().isoformat()
        if sync_status_key == "syncing_full":
            _set_status(db, "nvd_last_full_sync", now_iso)
        else:
            _set_status(db, "nvd_last_incremental_sync", now_iso)

    except Exception:
        # Status already set to "failed" inside the loop; just re-raise
        raise
    finally:
        db.close()


# ── Public API ────────────────────────────────────────────────────────────────

def sync_full(api_key: str | None = None) -> None:
    """
    Download ALL CVEs from NVD and upsert into cve_cache.

    Intended to be called in a daemon background thread:
        threading.Thread(target=sync_full, args=(key,), daemon=True).start()
    """
    _sync_pages(api_key, extra_params={}, sync_status_key="syncing_full")


def sync_incremental(api_key: str | None = None, days: int = 7) -> None:
    """
    Download CVEs modified in the last *days* days and upsert into cve_cache.

    Intended to be called in a daemon background thread.
    """
    now = datetime.utcnow()
    start = now - timedelta(days=days)

    # NVD date format: "2024-01-01T00:00:00.000 UTC+00:00"
    fmt = "%Y-%m-%dT%H:%M:%S.000 UTC+00:00"
    extra_params = {
        "lastModStartDate": start.strftime(fmt),
        "lastModEndDate": now.strftime(fmt),
    }
    _sync_pages(api_key, extra_params=extra_params, sync_status_key="syncing_incremental")


def get_sync_status(db) -> dict:
    """
    Return a dict summarising the current cache/sync state.

    Keys: status, progress, last_full, last_incremental, total_cached, last_error
    """
    keys = [
        "nvd_sync_status",
        "nvd_sync_progress",
        "nvd_last_full_sync",
        "nvd_last_incremental_sync",
        "nvd_total_cached",
        "nvd_sync_error",
    ]
    rows = {r.key: r.value for r in db.query(AppSetting).filter(AppSetting.key.in_(keys)).all()}

    return {
        "status":           rows.get("nvd_sync_status", "idle") or "idle",
        "progress":         rows.get("nvd_sync_progress", "") or "",
        "last_full":        rows.get("nvd_last_full_sync", "") or "",
        "last_incremental": rows.get("nvd_last_incremental_sync", "") or "",
        "total_cached":     rows.get("nvd_total_cached", "0") or "0",
        "last_error":       rows.get("nvd_sync_error", "") or "",
    }
