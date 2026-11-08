import asyncio, sys
sys.path.insert(0, "/root/aguard/experiments")
from dotenv import load_dotenv
load_dotenv("/root/aguard/experiments/.env")
from principals import PrincipalFactory
import benign, episodes, monitor

async def main():
    f, llm = PrincipalFactory(), benign.client()
    eps = episodes.make_matrix()                      # 40 attack + 120 benign, scale=1.0
    print("episodes:", len(eps), flush=True)
    await episodes.run_all(f, llm, eps)
    done = [r[0] for r in f.db.execute("select episode_id from ep_runs where status='done'")]
    print("episodes done:", len(done), flush=True)
    await monitor.run(done, ["small", "strong"])

asyncio.run(main())
