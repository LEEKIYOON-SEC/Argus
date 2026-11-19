import re
from typing import Dict, Optional

SOURCES = {
    "sigma": {"license": "DRL 1.1", "license_url": "https://github.com/SigmaHQ/Detection-Rule-License"},
    "splunk": {"license": "Apache-2.0",
               "license_url": "https://github.com/splunk/security_content/blob/develop/LICENSE"},
    "nuclei": {"license": "MIT",
               "license_url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md"},
    "et-open": {"license": "BSD", "license_url": "https://rules.emergingthreats.net/open/suricata-7.0/LICENSE"},
    "snort-community": {"license": "GPLv2", "license_url": "https://www.gnu.org/licenses/old-licenses/gpl-2.0.html"},
}

YARA_REPOS = {
    "neo23x0/signature-base": ("DRL 1.1", ""),
    "sekoia-io/community": ("DRL 1.1", ""),
    "ditekshen/detection": ("BSD-2-Clause", "Copyright 2021 by ditekSHen (https://github.com/ditekshen/detection)."),
    "volexity/threat-intel": ("BSD-2-Clause", "Copyright 2022 by Volexity, Inc."),
    "elceef/yara-rulz": ("MIT", "Copyright (c) 2022 Marcin Ulikowski"),
    "craiu/yararules": ("GPL-3.0", ""),
}

NETWORK_ENGINES = ("snort2", "snort3", "suricata5", "suricata7")
LINK_ONLY_ENGINES = ("nuclei",)

_GITHUB = re.compile(r"github\.com/+([^/\s]+)/+([^/\s#?]+)", re.I)


def source_of(rule: Dict) -> Optional[str]:
    engine = rule.get("engine") or ""
    if engine in NETWORK_ENGINES:
        return "snort-community" if "community" in (rule.get("source") or "").lower() else "et-open"
    return engine or None


def repo_of(url: str) -> str:
    m = _GITHUB.search(url or "")
    return f"{m.group(1)}/{m.group(2)}".lower() if m else ""


def et_open_sid_ok(sid: Optional[int]) -> bool:
    return sid is not None and 2000000 <= sid <= 2799999


def terms(rule: Dict) -> Dict:
    engine = rule.get("engine") or ""
    if engine == "yara":
        lic_url = str(rule.get("license_url") or "")
        if not lic_url.lower().startswith(("http://", "https://")):
            return {"license": "", "license_url": "", "holder": "", "link_only": True}
        name, holder = YARA_REPOS.get(repo_of(lic_url), ("", ""))
        return {"license": name, "license_url": lic_url, "holder": holder, "link_only": not name}
    base = SOURCES.get(source_of(rule) or "")
    if base is None:
        return {"license": str(rule.get("license") or ""), "license_url": str(rule.get("license_url") or ""),
                "holder": "", "link_only": engine in LINK_ONLY_ENGINES}
    return {"license": base["license"], "license_url": base["license_url"], "holder": "",
            "link_only": engine in LINK_ONLY_ENGINES}


def apply(rule: Dict) -> Dict:
    out = {k: v for k, v in rule.items() if k != "note"}
    t = terms(rule)
    out["license"] = t["license"]
    if out.get("engine") == "yara":
        out["license_url"] = t["license_url"]
        if t["holder"]:
            out["holder"] = t["holder"]
        else:
            out.pop("holder", None)
    else:
        out.pop("license_url", None)
        out.pop("holder", None)
    if t["link_only"]:
        out.pop("code", None)
        out["link_only"] = True
    else:
        out.pop("link_only", None)
    return out
