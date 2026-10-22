import datetime
import time
from typing import Callable, Dict, List, Optional, Tuple

from logger import logger

RULE_KEYS = ("network", "sigma", "yara", "nuclei", "splunk")


def _when(ts) -> Optional[datetime.datetime]:
    try:
        d = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)


def due(rows: Dict[str, Dict], grown: List[str], built_at: str) -> Tuple[List[Dict], List[Dict]]:
    """grown 가운데 추적 중이고 색인을 만든 뒤로 다시 보지 않은 CVE — (룰이 없던 것, 이미 룰이 있던 것)."""
    built = _when(built_at)
    if built is None:
        return [], []
    fresh: List[Dict] = []
    known: List[Dict] = []
    for cve in grown:
        row = rows.get(cve)
        if not row:
            continue
        last = _when(row.get("last_rule_check_at"))
        if last is not None and last >= built:
            continue
        (known if row.get("has_official_rules") else fresh).append(row)
    return fresh, known


def plan(db, grown: List[str], built_at: str, max_recheck: int) -> Tuple[List[Dict], List[Dict]]:
    """알림을 보낼 수 있는 재확인 대상(룰이 늘어난 CVE 먼저, 남는 자리는 기존 대상)과 조용히 바꿀 대상."""
    fresh: List[Dict] = []
    known: List[Dict] = []
    if grown and built_at:
        try:
            rows, _ = db.get_cves(grown)
            fresh, known = due(rows, grown, built_at)
        except Exception as e:
            logger.warning(f"룰이 늘어난 CVE 조회 실패({e}) — 기존 재확인만 한다")
    fresh = fresh[:max(0, max_recheck)]
    picked = {r["id"] for r in fresh}
    rest = max_recheck - len(fresh)
    regular = [r for r in db.get_rule_recheck_candidates(limit=rest) if r["id"] not in picked] if rest > 0 else []
    return fresh + regular, known


def refresh_known(db, search: Callable[[str], Tuple[Dict, bool]], rows: List[Dict],
                  now: Callable[[], str], soon: Callable[[], str],
                  deadline_ts: Optional[float] = None,
                  clock: Optional[Callable[[], float]] = None) -> int:
    """이미 룰이 있던 CVE 의 스냅샷을 지금 색인으로 다시 만든다. 알림은 보내지 않는다. 바꾼 건수를 돌려준다."""
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