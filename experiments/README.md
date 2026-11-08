# Experiment: can resource-keyed audit-trail monitoring catch distributed document-collection attacks?

Apart Research Swarm Alignment Hackathon, Nov 6-8 2026. Author: Enoch Aboluwarin Abe (independent).

## Preexisting-code boundary
Everything in `aguard/` up to git tag `pre-sprint` (commit 6e0ee4e) is preexisting (A-guard: OIDC
authorization server, MCP resource server, Postgres-enforced permissions, `agent_audit` with
`resource_id`). Everything in `experiments/` was written during the sprint. `aguard/` is unchanged
(see CHANGES_TO_AGUARD.md). The Adaption-generated datasets are in `experiments/data/`.

## SYNTHETIC ONLY
`attacks.py` simulates distributed collection of "confidential" documents against a fictional corpus,
through real MCP calls with verified identities. It must not be pointed at real data.

## Layout
- `exp_services.py`: second AS + MCP pair on 127.0.0.1:8180/8181 against DB `agurd_exp` (needs the schema from `aguard/db/schema.sql` applied to `agurd_exp`)
- `loaders.py`, `reset_corpus.py`: extract and clean the Adaption corpus, load 48 docs (10 CONFIDENTIAL, seed 42) under one owner
- `principals.py`: one DCR client per agent per episode (real auth-code + PKCE flow)
- `attacks.py` (A1 parallel slicing, A2 staged, deterministic success check), `benign.py` (LLM tool loop), `episodes.py`, `run_full.py`
- `views.py` (V1-V4), `monitor.py` (prompt, 3 readings, resumable), `analyze.py`, `baseline.py`, `figures.py`
- `modal_serve.py`, `modal_serve_strong.py`: vLLM servers (Qwen2.5-7B-Instruct as `small`, Qwen2.5-32B-Instruct-AWQ as `strong`)
- `results/`: CSVs, `summary.md`, figures, and `results.sqlite` (every episode, prompt and raw monitor output)

## Rerun
1. `modal deploy experiments/modal_serve.py` and `modal deploy experiments/modal_serve_strong.py` (proxy-auth tokens go in `.env`)
2. Create `experiments/.env` with `PG_PASSWORD`, `MODAL_BASE_URL`, `MODAL_BASE_URL_STRONG`, `MODAL_KEY`, `MODAL_SECRET`, `MODEL_SMALL=small`, `MODEL_STRONG=strong`, `MONITOR_TEMPERATURE=0.7`, `MAX_CALLS=30000` (never commit it)
3. `python experiments/exp_services.py start`, then `python experiments/reset_corpus.py`
4. `python experiments/run_full.py` (resumable: finished episodes and readings are skipped)
5. `python experiments/analyze.py`, `python experiments/baseline.py`, `python experiments/figures.py`

## Cost
About 10,000 LLM calls and 7.6M tokens in total (episodes plus monitor readings), on self-hosted
vLLM (A10G for `small`, L40S for `strong`), so the cost is GPU time and not per-token billing.
A pinned `MAX_CALLS` cap is enforced in `benign.py`.

See LIMITATIONS.md before interpreting any number.
