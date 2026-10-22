import datetime
import time
from typing import Callable, Dict, List, Optional, Tuple

from logger import logger

RULE_KEYS = ("network", "sigma", "yara", "nuclei", "splunk")
SETTLE = datetime.timedelta(hours=1)


def _when(ts) -> Optional[datetime.datetime]:
    try:
        d = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)


def _order(row: Dict):
    return (not row.get("is_kev"), -(row.get("cvss_score") or 0), -(row.get("epss_score") or 0), row["id"])


def due(rows: Dict[str, Dict], built_at: str,
        missing: Callable[[str, object], bool]) -> Tuple[List[Dict], List[Dict]]:
    built = _when(built_at)
    if built is None:
        return [], []
    fresh: List[Dict] = []
    known: List[Dict] = []
    for row in rows.values():
        last = _when(row.get("last_rule_check_at"))
        if last is not None and last >= built + SETTLE:
            continue
        if not missing(row["id"], row.get("rules_snapshot")):
            continue
        (known if row.get("has_official_rules") else fresh).append(row)
    return sorted(fresh, key=_order), sorted(known, key=_order)


def plan(db, ids: List[str], built_at: str, max_recheck: int,
         missing: Callable[[str, object], bool]) -> Tuple[List[Dict], List[Dict]]:
    fresh: List[Dict] = []
    known: List[Dict] = []
    if ids and built_at:
        try:
            fresh, known = due(db.get_rule_rows(ids), built_at, missing)
            logger.info(f"색인에는 있는데 화면에 없는 룰 — 룰이 없던 CVE {len(fresh):,}건 · "
                        f"이미 룰이 있던 CVE {len(known):,}건")
        except Exception as e:
            logger.warning(f"룰이 빠진 CVE 조회 실패({e}) — 기존 재확인만 한다")
    fresh = fresh[:max(0, max_recheck)]
    picked = {r["id"] for r in fresh}
    rest = max_recheck - len(fresh)
    regular = [r for r in db.get_rule_recheck_candidates(limit=rest) if r["id"] not in picked] if rest > 0 else []
    return fresh + regular, known


def refresh_known(db, search: Callable[[str], Tuple[Dict, bool]], rows: List[Dict],
                  now: Callable[[], str], soon: Callable[[], str],
                  deadline_ts: Optional[float] = None,
                  clock: Optional[Callable[[], float]] = None) -> int:
    clock = clock or time.time
    done = 0
    for row in rows:
        if deadline_ts is not None and clock() > deadline_ts:
            logger.warning("⏰ 시간 예산 도달 — 룰 스냅샷 갱신 중단 (남은 CVE 는 다음 실행이 이어받는다)")
            break
        cve_id = row["id"]
        try:
            rules, complete = search(cve_id)
        except Exception as e:
            logger.error(f"{cve_id} 룰 스냅샷 갱신 실패: {e}")
            continue
        stamp = now()
        if not complete:
            db.upsert_cve({"id": cve_id, "last_rule_check_at": soon(), "updated_at": stamp})
            continue
        if any(rules.get(k) for k in RULE_KEYS):
            db.upsert_cve({"id": cve_id, "has_official_rules": True, "rules_snapshot": rules,
                           "last_rule_check_at": stamp, "updated_at": stamp})
            done += 1
        else:
            db.upsert_cve({"id": cve_id, "last_rule_check_at": stamp, "updated_at": stamp})
    return done
