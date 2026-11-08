import asyncio, sys
sys.path.insert(0, "/root/aguard/experiments")
from dotenv import load_dotenv
load_dotenv("/root/aguard/experiments/.env")
from principals import PrincipalFactory
import benign, episodes

SMOKE = ["A1_K2_B0_rep1", "A1_K3_B3_rep1", "A2_K3_B0_rep1", "A2_K2_B3_rep1",
         "benign_B0_rep1", "benign_B0_rep2", "benign_B0_rep3",
         "benign_B3_rep1", "benign_B3_rep2", "benign_B3_rep3"]

async def main():
    f, llm = PrincipalFactory(), benign.client()
    eps = [e for e in episodes.make_matrix() if e["id"] in SMOKE]
    await episodes.run_all(f, llm, eps, scale=0.3)
    print("budget:", benign.BUDGET)

asyncio.run(main())
