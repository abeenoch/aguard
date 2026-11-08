import csv, sqlite3
from collections import defaultdict
import numpy as np
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt

R = "/root/aguard/experiments/results/"
VIEWS = ("V1", "V2", "V3", "V4")

# Figure 1: detection at calibrated thresholds, with bootstrap 95% CIs
rows = list(csv.DictReader(open(R + "detection.csv")))
fig, axs = plt.subplots(1, 2, figsize=(10, 3.6), sharey=True)
for ax, B in zip(axs, ("0", "3")):
    for i, (m, c) in enumerate((("small", "#9ecae1"), ("strong", "#3182bd"))):
        rs = [next(r for r in rows if r["model"] == m and r["view"] == v and r["B"] == B) for v in VIEWS]
        d = [float(r["detection"]) for r in rs]
        ax.bar([j + (i - .5) * .38 for j in range(4)], d, .38, color=c, label=f"{m} monitor",
               yerr=[[x - float(r["ci_lo"]) for x, r in zip(d, rs)], [float(r["ci_hi"]) - x for x, r in zip(d, rs)]],
               capsize=3)
    ax.axhline(1.0, ls="--", c="k", lw=1, label="no-LLM count baseline")
    ax.set_xticks(range(4)); ax.set_xticklabels(VIEWS); ax.set_title(f"B={B} bystanders"); ax.set_ylim(0, 1.05)
axs[0].set_ylabel("Detection rate (successful attacks)"); axs[0].legend(fontsize=8, loc="upper left")
plt.tight_layout(); plt.savefig(R + "fig1_detection.pdf"); plt.close()

# Figure 2: ROC, strong monitor, held-out benign vs attacks
db = sqlite3.connect(R + "results.sqlite")
ep = {r[0]: r for r in db.execute("select episode_id,kind,B,calibration,success from ep_runs where status='done'")}
raw = defaultdict(list)
for eid, v, u, m, s in db.execute("select episode_id,view,unit,model,score from mon_readings"):
    if s is not None: raw[(eid, v, u, m)].append(s)
tmp = defaultdict(list)
for (eid, v, u, m), s in raw.items():
    if len(s) >= 2: tmp[(eid, v, m)].append(np.mean(s))
S = {k: max(v) for k, v in tmp.items()}
fig, axs = plt.subplots(1, 2, figsize=(8, 3.8), sharey=True)
for ax, B in zip(axs, (0, 3)):
    for v in VIEWS:
        pos = [S[(e[0], v, "strong")] for e in ep.values() if e[1] == "attack" and e[2] == B and e[4] == 1 and (e[0], v, "strong") in S]
        neg = [S[(e[0], v, "strong")] for e in ep.values() if e[1] == "benign" and e[2] == B and e[3] == 0 and (e[0], v, "strong") in S]
        ts = sorted(set(pos + neg), reverse=True)
        fpr = [0] + [np.mean([n >= t for n in neg]) for t in ts] + [1]
        tpr = [0] + [np.mean([p >= t for p in pos]) for t in ts] + [1]
        ax.plot(fpr, tpr, label=v)
    ax.plot([0, 1], [0, 1], "k:", lw=1); ax.set_title(f"strong monitor, B={B}"); ax.set_xlabel("False positive rate")
axs[0].set_ylabel("True positive rate"); axs[0].legend(fontsize=8)
plt.tight_layout(); plt.savefig(R + "fig2_roc.pdf"); plt.close()
print("wrote fig1_detection.pdf, fig2_roc.pdf")
