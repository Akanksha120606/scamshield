import csv
import json
import time
import urllib.request

from eval_data import DATA
from rules import check_rules
from privacy import redact

API = "http://127.0.0.1:8000/analyze"
DELAY_SECONDS = 5  # pause between calls to stay inside the free-tier rate limit


def rules_only_flagged(text: str) -> bool:
    clean, _ = redact(text)
    return check_rules(clean)["score"] >= 30


def call_api(text: str) -> dict:
    body = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(API, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def metrics(pairs):
    """pairs = list of (truth, flagged) where both are True/False."""
    tp = sum(1 for t, f in pairs if t and f)
    fn = sum(1 for t, f in pairs if t and not f)
    fp = sum(1 for t, f in pairs if not t and f)
    tn = sum(1 for t, f in pairs if not t and not f)
    total = tp + fn + fp + tn
    acc = (tp + tn) / total if total else 0
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0
    return dict(tp=tp, fn=fn, fp=fp, tn=tn, acc=acc, prec=prec, rec=rec, f1=f1, fpr=fpr)


def show(name, m):
    print(f"\n{name}")
    print(f"  Accuracy:            {m['acc']*100:.1f}%")
    print(f"  Scams caught:        {m['rec']*100:.1f}%  ({m['tp']} of {m['tp'] + m['fn']})")
    print(f"  Precision:           {m['prec']*100:.1f}%")
    print(f"  F1 score:            {m['f1']*100:.1f}%")
    print(f"  False alarms:        {m['fpr']*100:.1f}%  ({m['fp']} of {m['fp'] + m['tn']} legitimate messages)")


rows = []
hybrid_pairs, rules_pairs = [], []
errors = 0
ai_fallbacks = 0

print(f"Running {len(DATA)} test messages. This takes a few minutes...\n")
for i, (text, label, category) in enumerate(DATA, 1):
    truth = bool(label)
    r_flag = rules_only_flagged(text)
    rules_pairs.append((truth, r_flag))

    try:
        d = call_api(text)
        h_flag = d["verdict"] != "Safe"
        if not d.get("ai_used"):
            ai_fallbacks += 1
        hybrid_pairs.append((truth, h_flag))
        verdict, score = d["verdict"], d["risk_score"]
        status = "OK " if h_flag == truth else "MISS"
    except Exception as e:
        errors += 1
        h_flag, verdict, score, status = None, "ERROR", -1, "ERR "
        print(f"  error on message {i}: {e}")

    print(f"[{i:02d}/{len(DATA)}] {status} {category:<14} -> {verdict} ({score})")
    rows.append([i, category, label, r_flag, h_flag, verdict, score, text])
    time.sleep(DELAY_SECONDS)

print("\n" + "=" * 54)
print(f"RESULTS on {len(DATA)} messages "
      f"({sum(l for _, l, _ in DATA)} scams, {sum(1 - l for _, l, _ in DATA)} legitimate)")
print("=" * 54)
show("Rules only (no AI)", metrics(rules_pairs))
if hybrid_pairs:
    show("ScamShield hybrid (rules + AI)", metrics(hybrid_pairs))

if errors:
    print(f"\nWarning: {errors} message(s) failed (server error). Re-run later for clean numbers.")
if ai_fallbacks:
    print(f"Warning: {ai_fallbacks} message(s) used the rules-only fallback because the AI was busy. "
          "Re-run later so the hybrid numbers reflect the full system.")

print("\nMistakes made by the hybrid system:")
found = False
for r in rows:
    _, cat, label, _, h_flag, verdict, score, text = r
    if h_flag is not None and h_flag != bool(label):
        found = True
        kind = "missed scam" if label else "false alarm"
        print(f"  - [{kind}] ({cat}, {verdict} {score}) {text[:90]}")
if not found:
    print("  none")

with open("eval_results.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["#", "category", "is_scam", "rules_flagged", "hybrid_flagged", "verdict", "score", "message"])
    w.writerows(rows)
print("\nFull results saved to eval_results.csv")