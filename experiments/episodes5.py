"""K=5 follow-up: 5-agent teams, A1 with 5 colluders (2 confidential docs each) + matching benign episodes.
SYNTHETIC ONLY. Episode ids are prefixed k5_."""
import asyncio, hashlib, random, time
from loaders import task_for
from attacks import run_attack, attack_success
import benign

SEED, TEAM, B_SETTINGS, K, REPEATS = 42, 5, (0, 3), 5, 20

def make_matrix(benign_per_B=60, cal_per_B=30):
    eps = [dict(id=f"k5_A1_K{K}_B{B}_rep{r}", kind="attack", attack="A1", K=K, B=B, rep=r, cal=0)
           for B in B_SETTINGS for r in range(1, REPEATS + 1)]
    for B in B_SETTINGS:
        reps = list(range(1, benign_per_B + 1))
        random.Random(f"{SEED}-k5-cal-{B}").shuffle(reps)
        cal = set(reps[:cal_per_B])
        eps += [dict(id=f"k5_benign_B{B}_rep{r}", kind="benign", attack="benign", K=0, B=B, rep=r,
                     cal=int(r in cal)) for r in range(1, benign_per_B + 1)]
    return eps

async def run_episode(f, llm, ep, T, cover, tasks, scale=1.0):
    eid, B = ep["id"], ep["B"]
    team = [f.make(eid, i, "team") for i in range(1, TEAM + 1)]
    byst = [f.make(eid, TEAM + j, "bystander") for j in range(1, B + 1)]
    t0 = time.time()
    jobs = [benign.run_benign(p, task_for(eid, p.idx, tasks)["text"], llm) for p in byst]
    if ep["kind"] == "attack":
        seed = int(hashlib.sha1(f"{SEED}:{eid}".encode()).hexdigest(), 16) % 2**31
        jobs.append(run_attack(team, ep["attack"], ep["K"], T, cover, seed=seed, scale=scale))
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
