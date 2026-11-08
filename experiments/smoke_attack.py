import asyncio, sys
sys.path.insert(0, "/root/aguard/experiments")
from dotenv import load_dotenv
load_dotenv("/root/aguard/experiments/.env")
from principals import PrincipalFactory
from attacks import corpus, run_attack, attack_success, _pg

async def main():
    T, cover = corpus(); f = PrincipalFactory()
    print("T =", T, "| cover docs:", len(cover))
    for attack, K in (("A1", 3), ("A2", 2)):
        eid = f"smoke_{attack}_K{K}"
        team = [f.make(eid, i, "team") for i in (1, 2, 3)]
        cols = await run_attack(team, attack, K, T, cover, seed=7, scale=0.2)
        ok, missing = attack_success(cols, T)
        print(attack, "K=%d" % K, "success:", ok, "missing:", missing)
        with _pg() as c:
            for r in c.execute("select to_char(ts,'HH24:MI:SS.MS'), client_id, resource_id from agent_audit "
                               "where client_id = any(%s) order by ts", ([p.client_id for p in team],)):
                print("  ", r, "COLLUDER" if r[1] in cols else "cover-only")

asyncio.run(main())