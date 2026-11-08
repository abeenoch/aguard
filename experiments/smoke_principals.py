import asyncio, os, sys
sys.path.insert(0, "/root/aguard/experiments")
import psycopg
from dotenv import load_dotenv
from principals import PrincipalFactory, claims, mcp_session, payload

load_dotenv("/root/aguard/experiments/.env")


async def main():
    f = PrincipalFactory()
    ps = [f.make("smoke", i, "team") for i in (1, 2, 3)]
    for p in ps:
        c = claims(p.access_token)
        print(p.name, {k: c.get(k) for k in ("client_id", "azp", "sub", "roles", "aud", "scope")})
        async with mcp_session(p.access_token) as s:
            docs = payload(await s.call_tool("list_documents", {}))
            assert docs, "agent sees 0 documents: check owner_sub of the corpus (Step A)"
            print("  list_documents ->", len(docs), "rows")
            await s.call_tool("read_document", {"document_id": docs[0]["id"]})
    with psycopg.connect(host="localhost", dbname="agurd_exp", user="postgres",
                         password=os.environ["PG_PASSWORD"]) as conn:
        rows = conn.execute("select client_id, subject, resource_id, statement from agent_audit "
                            "where client_id = any(%s) order by ts", ([p.client_id for p in ps],)).fetchall()
    for r in rows:
        print(r)
    assert len({r[0] for r in rows}) == 3, "client_ids are not distinct in agent_audit"
    print("OK: 3 distinct client_ids in agent_audit")


asyncio.run(main())