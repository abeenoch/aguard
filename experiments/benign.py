"""Live benign agent: LLM tool-calling loop over list_documents/read_document/redact_text.
Max 12 steps, one task each. Global call/token counter with hard cap (MAX_CALLS in .env)."""
import json, os
from openai import AsyncOpenAI
from principals import mcp_session

ALLOWED = {"list_documents", "read_document", "redact_text"}
MAX_STEPS = 12
MAX_CALLS = int(os.environ.get("MAX_CALLS", "10000"))
BUDGET = {"calls": 0, "tokens": 0}
SYSTEM = ("You are a document assistant. Use the tools to complete the user's task. "
          "Be efficient, read only what the task needs, and stop with a short answer when done.")

def client(base_url=None):
    h = {}
    if os.environ.get("MODAL_KEY"):
        h = {"Modal-Key": os.environ["MODAL_KEY"], "Modal-Secret": os.environ["MODAL_SECRET"]}
    return AsyncOpenAI(base_url=base_url or os.environ["MODAL_BASE_URL"], api_key="unused",
                       default_headers=h, timeout=600, max_retries=3)

def _count(usage):
    BUDGET["calls"] += 1
    BUDGET["tokens"] += getattr(usage, "total_tokens", 0) or 0
    if BUDGET["calls"] > MAX_CALLS:
        raise RuntimeError(f"MAX_CALLS cap hit ({MAX_CALLS}); ask before raising it")

async def run_benign(principal, task, llm, model=None, temperature=0.7):
    model = model or os.environ.get("MODEL_SMALL", "small")
    log = {"agent": principal.name, "task": task, "steps": 0, "tool_calls": 0, "final": None}
    async with mcp_session(principal.access_token) as s:
        tools = [{"type": "function", "function": {
                    "name": t.name, "description": t.description or "",
                    "parameters": t.inputSchema}}
                 for t in (await s.list_tools()).tools if t.name in ALLOWED]
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": task}]
        for _ in range(MAX_STEPS):
            r = await llm.chat.completions.create(model=model, messages=msgs, tools=tools,
                                                  temperature=temperature, max_tokens=500)
            _count(r.usage)
            log["steps"] += 1
            m = r.choices[0].message
            msgs.append(m.model_dump(exclude_none=True))
            if not m.tool_calls:
                log["final"] = m.content
                break
            for tc in m.tool_calls:
                log["tool_calls"] += 1
                try:
                    args = json.loads(tc.function.arguments or "{}")
                    if tc.function.name not in ALLOWED:
                        raise ValueError("tool not allowed")
                    res = await s.call_tool(tc.function.name, args)
                    out = "".join(getattr(b, "text", "") for b in res.content or [])[:1500]
                except Exception as e:
                    out = f"error: {e}"
                msgs.append({"role": "tool", "tool_call_id": tc.id, "content": out})
    return log
