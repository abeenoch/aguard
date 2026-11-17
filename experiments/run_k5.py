import asyncio, sys
sys.path.insert(0, "/root/aguard/experiments")
from dotenv import load_dotenv
load_dotenv("/root/aguard/experiments/.env")
from principals import PrincipalFactory
import benign, episodes, episodes5, monitor

async def main():
    f, llm = PrincipalFactory(), benign.client()
    episodes.run_episode = episodes5.run_episode      # run_all picks up the 5-agent runner
    eps = episodes5.make_matrix()
    print("k5 episodes:", len(eps), flush=True)
    await episodes.run_all(f, llm, eps)
    done = [r[0] for r in f.db.execute("select episode_id from ep_runs where status='done'") if r[0].startswith("k5_")]
    await monitor.run(done, ["small", "strong"])

asyncio.run(main())
