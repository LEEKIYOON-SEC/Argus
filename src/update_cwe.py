#!/usr/bin/env python3
import argparse
import datetime as dt
import io
import json
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(_ROOT, "docs", "js", "cwe-data.js")
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
TERMS_URL = "https://cwe.mitre.org/about/termsofuse.html"
TERMS_TEXT = (
    "CWE™ is free to use by any organization or individual for any research, development, and/or commercial "
    "purposes, per these CWE Terms of Use. Accordingly, The MITRE Corporation hereby grants you a non-exclusive, "
    "royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for such "
    "purposes is authorized on the condition that you reproduce MITRE’s copyright designation and this license "
    "in any such copy. CWE is a trademark of The MITRE Corporation."
)
ABSTRACTION = {"Pillar": "P", "Class": "C", "Base": "B", "Variant": "V", "Compound": "M"}
MIN_WEAKNESSES = 800

_TIMEOUT = 60


class CweError(Exception):
    pass


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_bytes(raw: bytes) -> bytes:
    """zip 이면 안의 cwec_*.xml 을, 아니면 그대로."""
    if raw[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            names = [n for n in z.namelist() if n.lower().endswith(".xml")]
            if len(names) != 1:
                raise CweError(f"zip 안의 XML 이 하나가 아님: {z.namelist()}")
            return z.read(names[0])
    return raw


def parse_catalog(raw: bytes) -> Dict:
    """CWE XML(또는 zip) → {version, date, weaknesses: {id: (코드, 이름)}, categories: {id: 이름}}"""
    data = _xml_bytes(raw)
    version = date = ""
    weaknesses: Dict[str, tuple] = {}
    categories: Dict[str, str] = {}
    for event, el in ET.iterparse(io.BytesIO(data), events=("start", "end")):
        tag = _local(el.tag)
        if event == "start":
            if tag == "Weakness_Catalog":
                version, date = el.get("Version", ""), el.get("Date", "")
            continue
        if tag == "Weakness":
            wid, name = el.get("ID", ""), (el.get("Name") or "").strip()
            if wid.isdigit() and name:
                code = "D" if el.get("Status") == "Deprecated" else ABSTRACTION.get(el.get("Abstraction", ""), "")
                if not code:
                    raise CweError(f"CWE-{wid}: 모르는 추상화 수준 {el.get('Abstraction')!r}")
                weaknesses[wid] = (code, name)
            el.clear()
        elif tag == "Category":
            cid, name = el.get("ID", ""), (el.get("Name") or "").strip()
            if cid.isdigit() and name:
                categories[cid] = name
            el.clear()
        elif tag in ("View", "External_Reference"):
            el.clear()
    if not re.match(r"^\d+\.\d+", version):
        raise CweError(f"CWE 판 번호를 읽지 못함: {version!r}")
    return {"version": version, "date": date, "weaknesses": weaknesses, "categories": categories}


def validate(catalog: Dict) -> None:
    live = sum(1 for code, _ in catalog["weaknesses"].values() if code != "D")
    if live < MIN_WEAKNESSES:
        raise CweError(f"약점이 {live}개뿐 — 잘린 파일로 보고 쓰지 않는다 (최소 {MIN_WEAKNESSES})")


def render_js(catalog: Dict, year: int) -> str:
    """화면이 읽는 JS — 번호순으로 늘 같은 모양(바뀐 판만 diff 에 남게)."""
    by_num = lambda d: dict(sorted(d.items(), key=lambda kv: int(kv[0])))
    payload = {
        "version": catalog["version"],
        "date": catalog["date"],
        "w": {k: f"{code}|{name}" for k, (code, name) in by_num(catalog["weaknesses"]).items()},
        "c": by_num(catalog["categories"]),
    }
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return (
        "/* 자동 생성 — src/update_cwe.py 가 MITRE CWE 목록에서 만든다. 손으로 고치지 않는다.\n"
        f" * CWE {catalog['version']} ({catalog['date']}) · 약점의 추상화 수준(w: 'P' Pillar · 'C' Class · 'B' Base · "
        "'V' Variant · 'M' Compound · 'D' 폐기)과\n"
        " * 공식 영문 이름, 분류(Category) 이름(c)만 옮겼다. 한국어 이름 · 풀이는 docs/js/cwe.js.\n"
        " *\n"
        f" * Copyright © 2006–{year}, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are "
        "trademarks of The MITRE Corporation.\n"
        f" * {TERMS_TEXT}\n"
        f" * ({TERMS_URL})\n"
        " */\n"
        "(function (root) {\n"
        "  'use strict';\n"
        f"  const data = {body};\n"
        "  root.ArgusCWEData = data;\n"
        "  if (typeof module !== 'undefined' && module.exports) module.exports = data;\n"
        "})(typeof window !== 'undefined' ? window : globalThis);\n"
    )


def _download(url: str) -> bytes:
    import requests
    r = requests.get(url, timeout=_TIMEOUT, headers={"User-Agent": "argus-cwe"})
    r.raise_for_status()
    return r.content


def _current(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="MITRE CWE 목록 → docs/js/cwe-data.js")
    parser.add_argument("--source", help="받아 둔 cwec_*.xml 또는 .zip (없으면 MITRE 에서 받는다)")
    parser.add_argument("--out", default=OUT_PATH)
    parser.add_argument("--dry-run", action="store_true", help="읽고 검증만 하고 쓰지 않는다")
    args = parser.parse_args(argv)
    try:
        if args.source:
            with open(args.source, "rb") as f:
                raw = f.read()
        else:
            raw = _download(CWE_URL)
        catalog = parse_catalog(raw)
        validate(catalog)
    except (OSError, CweError, ET.ParseError) as e:
        print(f"CWE 목록을 만들지 못함: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"CWE 목록을 받지 못함: {e}", file=sys.stderr)
        return 1
    text = render_js(catalog, dt.datetime.now(dt.timezone.utc).year)
    n_w, n_c = len(catalog["weaknesses"]), len(catalog["categories"])
    print(f"CWE {catalog['version']} ({catalog['date']}) · 약점 {n_w}개 · 분류 {n_c}개")
    if args.dry_run:
        return 0
    if _current(args.out) == text:
        print("바뀐 것 없음")
        return 0
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"→ {os.path.relpath(args.out, _ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
