"""
scripts/correlate_sessions.py
================================
Phase 7, extended: cross-protocol session correlation.

TWO separate, clearly-labeled signals — never merged into one silent
"same attacker" verdict, because they carry very different confidence:

1. IP + time-window matching (the original stopgap). High confidence,
   but breaks completely under IP rotation.

2. Behavioral similarity (NEW): compares sessions' feature vectors
   (via shared/features.py's extract_session_features() — the same
   function the classifier uses) across DIFFERENT IPs. Flags likely
   same-attacker pairs using a similarity SCORE, surfaced as a
   separate "possible match" list — not silently merged, since this
   signal is weaker and heuristic (cosine similarity over a handful
   of features), not trained behavioral fingerprinting. That's real
   future work (Phase 9, needs real traffic) — this is an honest,
   bounded step beyond pure IP matching, not a replacement for it.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shared"))

from core_db import get_all_sessions
from features import extract_session_features, FEATURE_NAMES

CORRELATION_WINDOW_SECONDS = 600
SIMILARITY_THRESHOLD = 0.90  # cosine similarity; conservative, flags only strong matches


def _parse_iso(ts):
    return datetime.fromisoformat(ts)


def correlate_by_ip_time(sessions, window_seconds=CORRELATION_WINDOW_SECONDS):
    by_ip = {}
    for s in sessions:
        by_ip.setdefault(s["source_ip"], []).append(s)

    entities = []
    for ip, ip_sessions in by_ip.items():
        ip_sessions.sort(key=lambda s: _parse_iso(s["first_seen"]))
        current = None
        for s in ip_sessions:
            first_seen = _parse_iso(s["first_seen"])
            last_seen = _parse_iso(s["last_seen"])
            if current is None:
                current = {"source_ip": ip, "protocols": {s["protocol"]},
                           "session_ids": [s["session_id"]], "first_seen": first_seen,
                           "last_seen": last_seen, "total_requests": s["request_count"]}
                continue
            gap = (first_seen - current["last_seen"]).total_seconds()
            if gap <= window_seconds:
                current["protocols"].add(s["protocol"])
                current["session_ids"].append(s["session_id"])
                current["last_seen"] = max(current["last_seen"], last_seen)
                current["total_requests"] += s["request_count"]
            else:
                entities.append(current)
                current = {"source_ip": ip, "protocols": {s["protocol"]},
                           "session_ids": [s["session_id"]], "first_seen": first_seen,
                           "last_seen": last_seen, "total_requests": s["request_count"]}
        if current is not None:
            entities.append(current)
    return entities


def _cosine_similarity(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def correlate_by_behavior(sessions, entities, threshold=SIMILARITY_THRESHOLD):
    """
    Flags pairs of sessions from DIFFERENT IPs (so NOT already merged by
    the IP+time pass) whose feature vectors are highly similar — a
    secondary signal for "possibly the same attacker, rotated IP."
    Never merges silently — returns a separate list of flagged pairs,
    each carrying its own similarity score so a human/downstream system
    can judge confidence rather than treating it as certain.
    """
    entity_ips = {e["source_ip"] for e in entities}
    feats = {}
    for s in sessions:
        try:
            feats[s["session_id"]] = (s["source_ip"], s["protocol"], extract_session_features(s["session_id"]))
        except Exception:
            continue

    flagged = []
    ids = list(feats.keys())
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            sid_a, sid_b = ids[i], ids[j]
            ip_a, proto_a, vec_a = feats[sid_a]
            ip_b, proto_b, vec_b = feats[sid_b]
            if ip_a == ip_b:
                continue  # already covered by IP+time correlation
            sim = _cosine_similarity(vec_a, vec_b)
            if sim >= threshold:
                flagged.append({
                    "session_a": sid_a, "ip_a": ip_a, "protocol_a": proto_a,
                    "session_b": sid_b, "ip_b": ip_b, "protocol_b": proto_b,
                    "similarity": round(sim, 3),
                })
    return flagged


def main():
    sessions = get_all_sessions()

    entities = correlate_by_ip_time(sessions)
    print(f"=== Signal 1: IP + time-window ({len(sessions)} sessions -> {len(entities)} entities) ===\n")
    for i, e in enumerate(entities, 1):
        multi = " <-- MULTI-PROTOCOL PIVOT" if len(e["protocols"]) > 1 else ""
        print(f"Entity {i}: {e['source_ip']}{multi}  protocols={sorted(e['protocols'])}  "
              f"sessions={len(e['session_ids'])}  requests={e['total_requests']}")

    flagged = correlate_by_behavior(sessions, entities)
    print(f"\n=== Signal 2: Behavioral similarity, different IPs ({len(flagged)} possible match(es)) ===")
    print("(heuristic cosine similarity over session features — a SIGNAL to investigate,")
    print(" not a verdict; real fingerprinting needs trained models + real traffic)\n")
    if not flagged:
        print("No cross-IP behavioral matches above threshold.")
    for f in flagged:
        print(f"  POSSIBLE MATCH (similarity={f['similarity']}): "
              f"{f['ip_a']} ({f['protocol_a']}) <-> {f['ip_b']} ({f['protocol_b']})")


if __name__ == "__main__":
    main()
