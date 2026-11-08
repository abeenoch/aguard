"""Episode runner. Episode = 3 team agents + B bystanders running concurrently.
Attack episode: team scripted (attacks.py), bystanders live LLM. Benign episode: everyone live LLM.
Resumable: episodes with status='done' in ep_runs are skipped. Bystanders are idx 4..3+B."""
import asyncio, json, random, sqlite3, time
from loaders import load_tasks, task_for
from attacks import corpus, run_attack, attack_success
import benign

SEED, B_SETTINGS, ATTACKS, K_VALUES, REPEATS = 42, (0, 3), ("A1", "A2"), (2, 3), 5

def make_matrix(benign_per_B=60, cal_per_B=30):
    eps = [dict(id=f"{a}_K{K}_B{B}_rep{r}", kind="attack", attack=a, K=K, B=B, rep=r, cal=0)
           for a in ATTACKS for K in K_VALUES for B in B_SETTINGS for r in range(1, REPEATS + 1)]
    for B in B_SETTINGS:
        reps = list(range(1, benign_per_B + 1))
        random.Random(f"{SEED}-cal-{B}").shuffle(reps)       # fixed-seed 50/50 split
        cal = set(reps[:cal_per_B])
        eps += [dict(id=f"benign_B{B}_rep{r}", kind="benign", attack="benign", K=0, B=B, rep=r,
                     cal=int(r in cal)) for r in range(1, benign_per_B + 1)]
    return eps

def init(db):
    db.execute("""CREATE TABLE IF NOT EXISTS ep_runs(episode_id TEXT PRIMARY KEY, kind TEXT, attack TEXT,
        K INT, B INT, rep INT, calibration INT, status TEXT, success INT, missing TEXT,
        colluders TEXT, t_start REAL, t_end REAL, logs TEXT, error TEXT)""")
    db.commit()

async def run_episode(f, llm, ep, T, cover, tasks, scale=1.0):
    eid, B = ep["id"], ep["B"]
    team = [f.make(eid, i, "team") for i in (1, 2, 3)]
    byst = [f.make(eid, 3 + j, "bystander") for j in range(1, B + 1)]
    t0 = time.time()
    jobs = [benign.run_benign(p, task_for(eid, p.idx, tasks)["text"], llm) for p in byst]
    if ep["kind"] == "attack":
        jobs.append(run_attack(team, ep["attack"], ep["K"], T, cover,
                               seed=int(__import__("hashlib").sha1(f"{SEED}:{eid}".encode()).hexdigest(), 16) % 2**31, scale=scale))
    else:
        jobs += [benign.run_benign(p, task_for(eid, p.idx, tasks)["text"], llm) for p in team]
    res = await asyncio.gather(*jobs, return_exceptions=True)
    errs = [repr(r) for r in res if isinstance(r, Exception)]
    out = dict(t0=t0, t1=time.time(), errs=errs, cols=None, ok=None, missing=None, logs=[])
    if ep["kind"] == "attack" and not isinstance(res[len(byst)], Exception):
        out["cols"] = res[len(byst)]
        out["ok"], out["missing"] = attack_success(out["cols"], T)
    out["logs"] = [r for r in res if isinstance(r, dict)]
    return out

async def run_all(f, llm, episodes, only=None, scale=1.0):
    db = f.db; init(db)
    T, cover = corpus(); tasks, _ = load_tasks()
    done = {r[0] for r in db.execute("select episode_id from ep_runs where status='done'")}
    for ep in episodes:
        if ep["id"] in done or (only and ep["id"] not in only):
            continue
        o = await run_episode(f, llm, ep, T, cover, tasks, scale)
        status = "error" if o["errs"] else "done"
        db.execute("INSERT OR REPLACE INTO ep_runs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (ep["id"], ep["kind"], ep["attack"], ep["K"], ep["B"], ep["rep"], ep["cal"], status,
                    None if o["ok"] is None else int(o["ok"]), json.dumps(o["missing"]),
                    json.dumps(o["cols"]), o["t0"], o["t1"], json.dumps(o["logs"])[:20000],
                    "; ".join(o["errs"])[:2000]))
        db.commit()
        print(f"{ep['id']:<22} {status:<5} success={o['ok']} calls={benign.BUDGET['calls']} "
              f"tokens={benign.BUDGET['tokens']} {o['t1']-o['t0']:.0f}s {o['errs'][:1]}")
