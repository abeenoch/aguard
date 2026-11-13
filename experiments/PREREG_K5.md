# K=5 follow-up: predictions written BEFORE any K=5 data exists
Setup: A1, K=5 colluders, 2 confidential docs each; 5-agent teams; B in {0,3}; same prompt, same
calibration procedure, same models. No changes after seeing data; all results reported.
P1. max_single (per-agent count) no longer separates attacks from benign (attack max 2 = benign max 2).
P2. union_all and union_team still separate (10 vs a small benign union), by construction of success.
P3. LLM V1 detection falls below the main experiment (strong: 0.60 at B=0, 0.65 at B=3).
P4. Strong V4 stays the best LLM view. V3 is uncertain.
P5. A positive evasion gap (V2 > V1) appears for the strong monitor. Low confidence.
