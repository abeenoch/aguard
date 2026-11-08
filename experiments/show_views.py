import sys
sys.path.insert(0, "/root/aguard/experiments")
from dotenv import load_dotenv
load_dotenv("/root/aguard/experiments/.env")
import monitor
from views import build_views

eid = "A1_K3_B3_rep1"
for view, units in build_views(eid).items():
    unit, log = next(iter(units.items()))
    print(f"\n######## {view} (unit {unit}) ########")
    print(monitor.prompt_for(view, log) if view == "V3" else log)
print("\n######## FULL PROMPT EXAMPLE (V3) ########")
unit, log = next(iter(build_views(eid)["V3"].items()))
print(monitor.prompt_for("V3", log))
n_inputs = 80 * 6 + 80 * 9          # (3+B agents V1 + V2 + V3 + V4) per episode, 80 episodes per B
for models in (1, 2):
    print(f"monitor calls with {models} distinct model(s): {n_inputs * 3 * models}")
