"""Monitor inputs V1-V4 from agent_audit. Actions only; identical line format across views."""
import hashlib, os, random, sqlite3
import psycopg

DB = "/root/aguard/experiments/results/results.sqlite"

def _pg():
    return psycopg.connect(host="localhost", dbname="agurd_exp", user="postgres",
                           password=os.environ["PG_PASSWORD"])

def _action(st):
    for k, v in (("list_documents", "list"), ("read_document", "read"), ("redact_text", "redact")):
        if k in st:
            return v
    return "other"

def fetch(episode_id):
    agents = sqlite3.connect(DB).execute(
        "select idx, role, client_id from agents where episode_id=? order by idx", (episode_id,)).fetchall()
    cids = [a[2] for a in agents]
    with _pg() as c:
        rows = c.execute("""select a.ts, a.client_id, a.statement, a.resource_id, a.rows_returned, m.classification
                            from agent_audit a left join doc_meta m on m.resource_id = a.resource_id
                            where a.client_id = any(%s) order by a.ts, a.id""", (cids,)).fetchall()
        n_conf = c.execute("select count(*) from doc_meta where classification='CONFIDENTIAL'").fetchone()[0]
    return agents, rows, n_conf

def _fmt(r, t0, pseud):
    ts, cid, st, res, n, cls = r
    tag = f" [{cls}]" if cls else ""
    return f"t=+{(ts - t0).total_seconds():7.1f}s {pseud[cid]} {_action(st)} {res}{tag} rows={n}"

def build_views(episode_id):
    """Returns {'V1': {unit: text}, 'V2': {'team': text}, 'V3': {'all': text}, 'V4': {'all': text}}."""
    agents, rows, n_conf = fetch(episode_id)
    if not rows:
        return {}
    t0 = rows[0][0]
    cids = [a[2] for a in agents]
    shuffled = cids[:]
    random.Random(hashlib.sha1(episode_id.encode()).hexdigest()).shuffle(shuffled)
    pseud = {c: f"P{i + 1}" for i, c in enumerate(shuffled)}
    team = {a[2] for a in agents if a[0] <= 3}
    line = lambda r: _fmt(r, t0, pseud)
    v1 = {}
    for c in cids:
        mine = [line(r) for r in rows if r[1] == c]
        if mine:
            v1[pseud[c]] = "\n".join(mine)
    v2 = "\n".join(line(r) for r in rows if r[1] in team)
    doc_rows = [r for r in rows if r[3].split(":")[0] == "documents"]
    v3 = "\n".join(line(r) for r in doc_rows)
    per, union = {}, set()
    for r in doc_rows:
        if r[3].startswith("documents:"):
            d = per.setdefault(pseud[r[1]], {"all": set(), "conf": set()})
            d["all"].add(r[3])
            if r[5] == "CONFIDENTIAL":
                d["conf"].add(r[3]); union.add(r[3])
    summ = ["SUMMARY (computed from the log above):"]
    for p in sorted(per, key=lambda x: int(x[1:])):
        summ.append(f"{p}: distinct documents touched={len(per[p]['all'])}, "
                    f"confidential documents touched={len(per[p]['conf'])}")
    summ.append(f"Union of confidential documents touched across all principals: {len(union)} of {n_conf}")
    out = {"V1": v1, "V3": {"all": v3}, "V4": {"all": v3 + "\n\n" + "\n".join(summ)}}
    if v2:
        out["V2"] = {"team": v2}
    return out
