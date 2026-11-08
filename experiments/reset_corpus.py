#!/usr/bin/env python3
"""Load the selected Adaption corpus into agurd_exp (48 docs, 10 CONFIDENTIAL, one owner, shuffled ids).
Refuses any DB other than agurd_exp. Idempotent; wipes documents, doc_meta and agent_audit there."""
import os, sys
sys.path.insert(0, "/root/aguard/experiments")
import psycopg
from dotenv import load_dotenv
from loaders import select_corpus

load_dotenv("/root/aguard/experiments/.env")
OWNER = "usr_alice"
docs, _ = select_corpus()

with psycopg.connect(host="localhost", dbname="agurd_exp", user="postgres",
                     password=os.environ["PG_PASSWORD"]) as conn:
    cur = conn.cursor()
    cur.execute("select current_database()")
    assert cur.fetchone()[0] == "agurd_exp", "wrong database"
    cur.execute("truncate documents, doc_meta, agent_audit restart identity")
    for d in docs:
        cur.execute("insert into documents (owner_sub, title, body, internal_notes) values (%s,%s,%s,'')",
                    (OWNER, d["title"], d["body"]))
    cur.execute("""insert into doc_meta (resource_id, classification, owner_sub)
                   select 'documents:' || id,
                          case when title like 'CONFIDENTIAL -%%' then 'CONFIDENTIAL' else 'NON_CONFIDENTIAL' end,
                          owner_sub from documents""")
    cur.execute("select count(*), count(distinct title), count(distinct owner_sub) from documents")
    total, titles, owners = cur.fetchone()
    cur.execute("select count(*) from doc_meta where classification='CONFIDENTIAL'")
    conf = cur.fetchone()[0]
    cur.execute("select count(*) from documents where title like 'CONFIDENTIAL -%'")
    conf_title = cur.fetchone()[0]
    cur.execute("""select count(*) from doc_meta m left join documents d
                   on m.resource_id = 'documents:' || d.id where d.id is null""")
    orphans = cur.fetchone()[0]
    print(dict(total=total, titles=titles, owners=owners, conf_meta=conf, conf_title=conf_title, orphans=orphans))
    assert (total, titles, owners, conf, conf_title, orphans) == (48, 48, 1, 10, 10, 0), "checks failed"
    cur.execute("select id from documents where title like 'CONFIDENTIAL -%' order by id")
    print("T =", [r[0] for r in cur.fetchall()])
print("corpus OK")
