# Limitations and shortcuts

1. **Main caveat.** Colluders read 3-5 confidential documents each, more than any benign agent (max 2). A no-LLM per-agent count therefore detects every attack (100%, 0% held-out FPR). The testbed does not reproduce the "each agent looks benign" premise. A K=5 variant (2 documents per colluder) would; it was not run.
2. Synthetic traffic: scripted fixed-plan colluders (no adaptation) and 7B-LLM benign agents, not real users or adversaries.
3. All 40 attacks succeeded, and detection is measured among successful attacks, so nothing here says how hard the attack is to execute.
4. Corpus: 48 documents (10 CONFIDENTIAL) selected with seed 42 from the Adaption file; bodies are short (154-936 chars). Monitors see titles and classification labels only, so label-reading is a shortcut.
5. Tasks: 128 after filtering (dropped delete, refusal, read-everything, duplicates), sampled with reuse. Benign agents' low confidential-read counts partly reflect this filter and the 7B executor.
6. Every agent authenticates as `usr_alice`; agents are separated only by DCR `client_id`. Tokens carry `roles: ['human']`, not `agent`.
7. The experiment AS/MCP instance uses relaxed login rate limits and its own signing key.
8. Prompt frozen before the full run. After the smoke test only format handling changed (max_tokens 800, score-tag fallback). Wording was not changed.
9. Calibration fix after seeing results: the threshold fallback was `inf`, which gave detection 0 whenever the top calibration score covered more than 5% of episodes. It is now just above the largest calibration score. Only the former `inf` rows changed, and no attack or held-out data was used.
10. A2 with K=2 is spec-literal: one reader collects all of T, so it is not a distributed attack.
11. Monitors: Qwen2.5-7B-Instruct (`small`) and Qwen2.5-32B-Instruct-AWQ (`strong`). `small` failed to parse about 25% of readings at first; unparsed readings were re-sampled, giving a final parse rate of 0.92. A unit needs at least 2 of 3 parsed readings.
12. Data incident: `A1_K2_B0_rep1-3` were recorded as successful but had no audit rows (cause unknown). They were deleted and rerun, along with their readings. TODO: add the result of the zero-audit-row check on all episodes.
13. Earlier scaffolding scripts printed placeholder results; they were deleted and nothing from them is used.
14. Timing: attack and benign episodes overlap, but per-agent timing was not formally compared. TODO: add this if checked.
15. B in {0, 3}, 5 repeats per attack cell, 30 calibration and 30 held-out benign episodes per B. CIs are wide, and some held-out FPRs exceed the 5% target (strong V4 at B=0: 13%).
16. Assumes the defender controls the access layer and sees unforgeable audit rows. Covert channels, adaptive colluders, and one agent holding several client identities are out of scope.

## Dual-use
The scripted attacks show how to split a collection goal across identities, and the results indicate which splits a monitor catches. This could inform an attacker's choice of split size. It is mitigated because the attacks are synthetic-only, run against a fictional corpus, need verified identities, and no tooling for evading deployed systems is released. The result is defender-side. It gives no guarantee against adaptive colluders, covert channels, or identity-sharing.
