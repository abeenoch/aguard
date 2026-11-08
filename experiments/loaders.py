"""Extract + validate + clean the Adaption datasets. Report: experiments/results/loader_report.json."""
import hashlib, json, random, re
from collections import Counter
from pathlib import Path

D = Path("/root/aguard/experiments/data")
REPORT = Path("/root/aguard/experiments/results/loader_report.json")
SEED = 42
JUNK = re.compile(r"^\W*(Step \d|This request cannot)", re.I)
SEP = re.compile(r"^\W*(Document \d+|-{3,})\W*$", re.I)

def _clean_title(s):
    s = re.sub(r"[*#]", "", s).strip()
    s = re.sub(r"^\d+\.\s*", "", s)
    return re.sub(r"^Title:\s*", "", s).strip()

def extract_blocks():
    raw = json.load(open(D / "northfield_logistics_docs.json"))
    blocks = []
    for item, r in enumerate(raw):
        t = r["enhanced_completion"].strip()
        if JUNK.match(t):
            continue
        lines = t.split("\n")
        starts = []
        for k, l in enumerate(lines):
            if re.match(r"\W*Category\W*:", l):
                j = k - 1
                while j >= 0 and (not lines[j].strip() or SEP.match(lines[j])):
                    j -= 1
                if j >= 0:
                    title = _clean_title(lines[j])
                    if not title.startswith("Category") and len(title) <= 120:
                        starts.append((j, title))
        for n, (j, title) in enumerate(starts):
            end = starts[n + 1][0] if n + 1 < len(starts) else len(lines)
            body_lines = [l for l in lines[j + 1:end] if not SEP.match(l)]
            body = re.sub(r"^\W*Body\W*:\s*", "", "\n".join(body_lines).strip(), flags=re.I | re.M).strip()
            blocks.append({"item": item, "title": title, "body": body})
    return blocks

def select_corpus(n_conf=10, n_non=38, seed=SEED):
    seen, conf, non = set(), [], []
    for b in extract_blocks():
        if b["title"] in seen or not (150 <= len(b["body"]) <= 6000):
            continue
        seen.add(b["title"])
        if b["title"].startswith("CONFIDENTIAL -"):
            conf.append(b)
        elif "CONFIDENTIAL" not in b["title"].upper():
            non.append(b)
    if len(conf) < n_conf or len(non) < n_non:
        raise SystemExit(f"not enough docs: conf={len(conf)} non={len(non)}")
    rng = random.Random(seed)
    chosen = rng.sample(conf, n_conf) + rng.sample(non, n_non)
    rng.shuffle(chosen)          # ids must not reveal classification
    return chosen, {"candidates_conf": len(conf), "candidates_non": len(non)}

REFUSAL_CAT = re.compile(r"access_denied|limitation|error_|unavailable|unsupported|missing_data|external_data|unable", re.I)
BAD = {
    "doc_id": re.compile(r"document id|doc id|documents:\d|\bid\s*#?\d+", re.I),
    "bypass_permissions": re.compile(r"bypass|permission|access control|override|without (authori|approval)", re.I),
    "copy_out": re.compile(r"copy (the )?data|copy .{0,30}(out|outside|externally)|export|exfiltrat|download all|send .{0,30}external", re.I),
    "read_everything": re.compile(r"everything|all (of )?(the )?documents|every document|entire (document )?(store|corpus)|each document", re.I),
    "delete": re.compile(r"\bdelete|\bremove (the )?(file|document)", re.I),
}

def load_tasks():
    raw = json.load(open(D / "internal_doc_ai_tasks.json"))
    tasks, seen, drops = [], set(), Counter()
    for r in raw:
        text = r["enhanced_prompt"].strip()
        key = re.sub(r"\W+", " ", text.lower()).strip()
        if key in seen:
            drops["duplicate"] += 1; continue
        seen.add(key)
        try: meta = json.loads(r["enhanced_completion"])
        except Exception: meta = {}
        cat = str(meta.get("category") or "")
        if REFUSAL_CAT.search(cat):
            drops["refusal_category"] += 1; continue
        reason = next((k for k, rx in BAD.items() if rx.search(text)), None)
        if reason:
            drops[reason] += 1; continue
        tasks.append({"id": hashlib.sha1(key.encode()).hexdigest()[:10], "text": text,
                      "category": cat or None, "expected_reads": meta.get("expected_reads")})
    return tasks, drops

def task_for(episode_id, idx, tasks, seed=SEED):
    h = int(hashlib.sha1(f"{seed}:{episode_id}:{idx}".encode()).hexdigest(), 16)
    return tasks[h % len(tasks)]

PII = {"email": re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
       "phone": re.compile(r"\b\d{3}[-. ]\d{4}\b|\(?\b\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b"),
       "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
       "card": re.compile(r"\b(?:\d[ -]?){13,16}\b")}

if __name__ == "__main__":
    docs, info = select_corpus()
    tasks, drops = load_tasks()
    conf = [d for d in docs if d["title"].startswith("CONFIDENTIAL -")]
    pii = {k: sum(len(rx.findall(d["title"] + " " + d["body"])) for d in docs) for k, rx in PII.items()}
    doms = Counter(m.split("@")[1].lower() for d in docs for m in PII["email"].findall(d["body"]))
    rep = {"docs": len(docs), "confidential": len(conf), **info, "tasks_kept": len(tasks),
           "task_drops": dict(drops), "tasks_expected_reads_gt_12": sum((t["expected_reads"] or 0) > 12 for t in tasks),
           "pii_pattern_counts": pii, "email_domains": dict(doms.most_common(10)),
           "body_len_min_max": [min(len(d["body"]) for d in docs), max(len(d["body"]) for d in docs)]}
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    json.dump(rep, open(REPORT, "w"), indent=1)
    print(json.dumps(rep, indent=1))
    print("\nsample titles:"); [print(" ", d["title"][:70]) for d in docs[:8]]
    assert len(docs) == 48 and len(conf) == 10
