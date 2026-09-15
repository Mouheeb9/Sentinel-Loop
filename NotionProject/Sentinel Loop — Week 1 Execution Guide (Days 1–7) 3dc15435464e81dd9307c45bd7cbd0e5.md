# Sentinel Loop — Week 1 Execution Guide (Days 1–7)

<aside>
📌

**How to use this page.** Every day has three blocks: what you do together, what each of you does alone, and a checkpoint that is either passed or not passed. Do not start the next day with a failed checkpoint. Resources are inside the toggle at the end of each day — read the linked thing *before* writing the code for that step, not after you are stuck.

Replace **Partner (Security)** with your friend's actual name once you copy this page.

</aside>

---

# Before Day 1 — accounts and machines

- [ ]  Anthropic API key with a spend limit set (start at 20 USD for week 1, you will use far less)
- [ ]  GitHub org or shared repo, both with write access
- [ ]  Langfuse Cloud free tier account — do **not** self-host Langfuse in week 1, the v3 stack needs ClickHouse, Redis and MinIO and it will eat a full day for zero portfolio value
- [ ]  Docker Desktop or Docker Engine on both machines
- [ ]  approx. 30 GB free disk (the telemetry corpora are large)
- [ ]  Python 3.12 and `uv` installed on both machines
- [ ]  Optional, only if you want live telemetry later: one Windows 10/11 VM. Not needed this week.

<aside>
⚠️

If you share one physical machine for a session, set `git config user.email` per session or use `Co-authored-by:` trailers in the commit message. The contribution graph is part of the portfolio. A repo where one person made 94 percent of commits makes the other person look like a passenger.

</aside>

---

# Ground rules for the whole week

**Daily rhythm**

1. 15-minute standup in the morning: what I finished, what I am blocked on, what I touch today.
2. Two solo blocks during the day. No pairing except where this page says to pair.
3. Evening: open PRs, review each other's, merge. Nothing sits unmerged overnight.

**Git**

- `main` is protected. Both of you require one review to merge. No exceptions, including for yourself.
- Branch naming: `ai/<thing>` for Mouheb, `sec/<thing>` for Partner. Instantly readable history.
- Conventional commits (`feat:`, `fix:`, `docs:`, `data:`). Costs nothing, reads professionally.

**Repo layout — create this on Day 1 and do not improvise later**

```
sentinel-loop/
├── docker-compose.yml
├── pyproject.toml
├── .env.example              # never commit .env
├── src/sentinel/
│   ├── schemas.py            # THE CONTRACTS — changed only by joint PR
│   ├── ingest/               # Mouheb
│   ├── retrieval/            # Mouheb
│   ├── graph/                # Mouheb
│   ├── tools/                # Mouheb
│   └── validation/           # Partner
├── evals/
│   ├── run.py                # Mouheb — the runner
│   └── scorers.py            # Partner — the scoring logic
├── injection/
│   ├── cases/                # Partner — payload corpus
│   ├── runner.py             # Partner
│   └── defenses/             # Mouheb
├── data/
│   ├── golden/               # Partner — triage eval set
│   └── validation/           # Partner — held-out EVTX, never touched by golden/
├── docs/
│   ├── labeling-guide.md     # Partner
│   ├── threat-model.md       # Partner
│   ├── week1-retro.md        # joint
│   └── adr/                  # each writes the ADR for the other's biggest decision
└── tests/
```

---

# Day 1 — Repo, environment, and the five contracts

## Together (most of the day)

**Morning, approx. 2h — environment**

- [ ]  Create the repo, MIT license, README with a one-paragraph pitch of the project (write it now, it forces clarity)
- [ ]  Turn on branch protection: require a PR, require one approval, no force push to `main`
- [ ]  `pyproject.toml` with `uv`. Dependencies for now: `pydantic`, `langgraph`, `langchain-anthropic`, `psycopg[binary]`, `pgvector`, `pytest`, `ruff`
- [ ]  `docker-compose.yml` with one service: `pgvector/pgvector:pg16`, volume-mounted, port 5432, plus an init SQL that runs `CREATE EXTENSION vector;`
- [ ]  `pre-commit` with `ruff check` and `ruff format`. Two minutes to set up, saves every future style argument.
- [ ]  `.env.example` listing every key by name with empty values. `.env` goes in `.gitignore` on the first commit, not the fifth.

**Afternoon, approx. 3h — the contracts session**

This is the most important three hours of the week. You write `src/sentinel/schemas.py` together, out loud, on one screen. Once merged, it changes only by a PR you both approve.

```python
# src/sentinel/schemas.py — sketch, fill in together

class Event(BaseModel):
    """One normalized log event. Every source flattens into this."""
    event_id: str
    timestamp: datetime
    source: Literal["windows_sysmon", "linux_auditd", "aws_cloudtrail", "guardduty"]
    host: str
    user: str | None
    process: ProcessInfo | None
    network: NetworkInfo | None
    raw: dict                             # original event, untouched
    untrusted_fields: list[str]           # JSON paths an attacker controls

class Alert(BaseModel):
    alert_id: str
    detection_name: str
    severity: Literal["low", "medium", "high", "critical"]
    events: list[Event]

class TriageVerdict(BaseModel):
    verdict: Literal["true_positive", "false_positive", "needs_review"]
    confidence: float = Field(ge=0, le=1)
    technique_ids: list[str]              # pattern: T dddd optionally .ddd
    reasoning: str
    evidence_refs: list[str]              # JSON paths INTO the alert, not prose
    ioc_refs: list[str]

class ValidationResult(BaseModel):
    compiled: bool
    compile_errors: list[str]
    true_positives: int
    false_positives: int
    fp_rate: float
    failed_samples: list[FailedSample]
    feedback: str                         # structured text the repair loop reads

class InjectionCase(BaseModel):
    case_id: str
    payload: str
    target_field: str                     # JSON path where it gets embedded
    category: Literal["direct_override", "fake_system_msg", "encoded",
                      "context_stuffing", "tool_hijack"]
    expected_safe_behavior: str
    success_signal: str                   # how you decide the attack worked
```

<aside>
🔑

Two fields carry the whole project and are easy to skip on Day 1.

**`Event.untrusted_fields`** is what later lets you defend structurally instead of begging the model in a prompt. Retrofitting it in Week 4 is painful.

**`TriageVerdict.evidence_refs` as JSON paths** is what makes hallucination detection mechanical: an IOC in the output that is not in the input is a set difference, not a judgement call.

</aside>

<aside>
✅

**Checkpoint Day 1.** Both machines run `docker compose up` and connect to Postgres with the vector extension present. `pytest` runs green on one trivial test. `schemas.py` is merged through a PR with a review, and the commit is tagged `v0.1-contracts`.

</aside>

- **Resources for Day 1**
    - Pydantic v2 — models, `Literal`, `Field` constraints, validators: [docs.pydantic.dev](https://docs.pydantic.dev/latest/concepts/models/)
    - uv project management (replaces pip + venv + poetry): [docs.astral.sh/uv](https://docs.astral.sh/uv/guides/projects/)
    - pgvector, including the Docker image and index types: [github.com/pgvector/pgvector](https://github.com/pgvector/pgvector)
    - Ruff, one tool for lint and format: [docs.astral.sh/ruff](https://docs.astral.sh/ruff/)
    - GitHub branch protection rules: [docs.github.com](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
    - Conventional Commits, five minutes to read: [conventionalcommits.org](https://www.conventionalcommits.org/)
    
    **Skill being learned:** interface-first design. The reason two-person projects collapse in week 3 is that nobody wrote the contract in week 1.
    

---

# Day 2 — First telemetry in, labeling standard written

## Mouheb (AI) — normalize one source properly

- [ ]  Pull a *subset* of `OTRF/Security-Datasets`. Do not clone the whole thing. Pick the Windows atomic datasets covering 8 to 10 distinct techniques to start.
- [ ]  Read three raw samples by hand before writing any parser. Know what the JSON actually looks like.
- [ ]  Write `src/sentinel/ingest/sysmon.py`: raw Sysmon JSON to `Event`. Windows Sysmon only today — it will be roughly 70 percent of your golden set, so it earns the first pass.
- [ ]  Create `config/untrusted_fields.yaml`: per source, the JSON paths an attacker can influence (process command line, image path, parent command line, user agent, file name, registry value data). Your partner reviews and extends this — it is the seed of the threat model.
- [ ]  Put 10 raw samples in `tests/fixtures/` and write a test asserting normalization is stable and schema-valid.

## Partner (Security) — write the labeling guide before labeling

<aside>
🎯

The instinct is to start labeling immediately. Resist it. An unwritten standard produces a dataset only you can reproduce, and a dataset nobody can reproduce is not evidence of anything.

</aside>

- [ ]  Write `docs/labeling-guide.md` covering:
    - What makes an alert a **true positive** (adversary behavior present) versus **benign but noisy** (legitimate activity a naive rule would flag: admin scripts, backup jobs, software deployment, vulnerability scanners)
    - How to assign technique IDs: one primary, optional secondaries, and what to do when an event maps to a sub-technique versus its parent
    - Tie-break rules for the ambiguous cases you will hit constantly
    - **The partial-credit spec**, which decides what your accuracy number even means. Proposed starting point: exact sub-technique match 1.0, correct parent technique 0.5, correct tactic only 0.25, wrong 0.0
- [ ]  Define the JSONL row format: `alert_id`, `label`, `technique_ids`, `source_dataset`, `rationale` (one line), `labeler`, `labeled_at`

## Together — evening, approx. 2h

- [ ]  Label the first 40 alerts **side by side, out loud**. Disagree deliberately.
- [ ]  Every disagreement becomes an amendment to the labeling guide. Record how many of the 40 you initially disagreed on — that number goes in the README later and it is a genuinely impressive thing to have measured.

<aside>
✅

**Checkpoint Day 2.** Ten real Sysmon samples become schema-valid `Event` objects and the test passes. `labeling-guide.md` is merged. 40 labels are committed to `data/golden/labels.jsonl` with the initial disagreement rate written down.

</aside>

- **Resources for Day 2**
    - Security-Datasets (Mordor) — labeled, ATT&CK-mapped telemetry: [github.com/OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets)
    - Splunk attack_data, a second corpus with different coverage: [github.com/splunk/attack_data](https://github.com/splunk/attack_data)
    - Sysmon event reference, the community guide is the best free one: [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
    - MITRE ATT&CK technique pages — read five in full, not summaries: [attack.mitre.org](https://attack.mitre.org/techniques/enterprise/)
    - Palantir's Alerting and Detection Strategy framework, the best short read on what a rigorous detection definition looks like: [github.com/palantir/alerting-detection-strategy-framework](https://github.com/palantir/alerting-detection-strategy-framework)
    
    **Skill being learned:** dataset design. Labeling is not data entry, it is the act of defining what correct means. This is the part most portfolio projects skip and the part interviewers probe.
    

---

# Day 3 — Retrieval corpus, and the labeling grind

## Mouheb (AI) — build retrieval that actually retrieves

- [ ]  Pull ATT&CK Enterprise from `mitre-attack/attack-stix-data`. Chunk **one technique per chunk**: ID, name, description, detection guidance, data sources, platforms. Chunking by page or by fixed token count destroys the structure that makes this corpus useful.
- [ ]  Pull `SigmaHQ/sigma`. One rule per chunk, keeping title, logsource and tags in the chunk text — the tags contain ATT&CK IDs and are strong retrieval signal.
- [ ]  Embed with a cheap model. Store in pgvector with an HNSW index.
- [ ]  Implement `retrieve(query, k, logsource=None, platform=None)` as **hybrid**: vector similarity plus metadata filtering. Pure semantic search over security text is mediocre because half the signal is exact identifiers.
- [ ]  Write 20 probe queries by hand (a described behavior, the technique you expect back). Measure recall at 5. Record it.

<aside>
💡

This mini-eval costs an hour and prevents a specific week-2 disaster: your triage accuracy looks bad, you spend three days tuning prompts, and the real cause was retrieval never surfacing the right technique.

</aside>

## Partner (Security) — labels 41 to 100, plus threat model start

- [ ]  Label alerts 41 to 100 following the guide. Log any case that forces a guide amendment.
- [ ]  Start `docs/threat-model.md`. One table per telemetry source with columns: field name, JSON path, who controls it, max realistic length, does it reach the model.
- [ ]  Flag every field where an attacker has free-text control. Those are your Week 2 injection targets and this table is what generates them.

<aside>
✅

**Checkpoint Day 3.** Recall at 5 is 0.8 or better on the 20 probe queries, or you have written down why it is not and what you changed. 100 labels committed. Threat model covers at least the Windows Sysmon source end to end.

</aside>

- **Resources for Day 3**
    - ATT&CK STIX data, the machine-readable source: [github.com/mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
    - SigmaHQ rules and the Sigma specification: [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) and [sigmahq.io](https://sigmahq.io/)
    - pgvector indexing — HNSW versus IVFFlat, and when each wins: [pgvector indexing docs](https://github.com/pgvector/pgvector#indexing)
    - Anthropic on contextual retrieval, the single most useful thing to read before chunking anything: [anthropic.com/news/contextual-retrieval](https://www.anthropic.com/news/contextual-retrieval)
    - OWASP Top 10 for LLM Applications, read LLM01 today so the threat model has vocabulary: [genai.owasp.org/llm-top-10](https://genai.owasp.org/llm-top-10/)
    
    **Skill being learned:** retrieval evaluation. Anyone can call an embedding API. Measuring whether retrieval works, before blaming the model, is the part that separates an AI engineer from someone who wired up a tutorial.
    

---

# Day 4 — The graph skeleton, and the golden set closes

## Mouheb (AI) — LangGraph, stubbed but real

- [ ]  Define `SentinelState` as a typed dict: the alert, retrieved context, the verdict, the draft rule, validation results, attempt counter.
- [ ]  Build the graph with all nodes present and stubbed: `ingest → enrich → triage → route → rule_gen → validate → repair → output`.
- [ ]  Implement the conditional edges properly. Route on verdict, and on whether existing Sigma coverage was found. The repair edge loops back with a max attempt count. **Getting the edges right while nodes are stubs is much easier than debugging both at once.**
- [ ]  Wire the Langfuse callback handler. Every run produces a trace, tagged with the config name.
- [ ]  `python -m sentinel.run --alert data/golden/alert_001.json` runs end to end and prints a stub verdict.

## Partner (Security) — finish the set, design the attacks

- [ ]  Label 101 to 150. Target composition: 100 true positives spanning 20 or more techniques, 50 benign-but-noisy.
- [ ]  Freeze it: commit as `data/golden/v1.jsonl`, tag `golden-v1`. Any later change is a new version with a changelog line.
- [ ]  Write `injection/cases/taxonomy.md`: five categories, eight payloads each, as a table. Design only today, no implementation. Columns: category, payload text, target field, what a safe agent should do, how you detect it failed.

<aside>
🚧

**Hard gate.** The golden set must be complete and frozen before Week 2 starts. Every metric in this project is measured against it. If it is not done by end of Day 4, both of you work on labeling on Day 5 and the schedule slips by a day. That is a much smaller cost than discovering in Week 3 that your numbers mean nothing.

</aside>

<aside>
✅

**Checkpoint Day 4.** An alert flows through every node of the graph and produces output, with a visible Langfuse trace. `golden-v1` is tagged. Injection taxonomy table is written.

</aside>

- **Resources for Day 4**
    - LangGraph — state, nodes, conditional edges. Work through the quickstart, then the conditional branching guide: [langchain-ai.github.io/langgraph](https://langchain-ai.github.io/langgraph/)
    - LangGraph state reducers, the concept people get wrong first: [low-level concepts](https://langchain-ai.github.io/langgraph/concepts/low_level/)
    - Langfuse tracing and its LangGraph integration: [langfuse.com/docs](https://langfuse.com/docs)
    - Simon Willison's prompt injection archive, for grounding the taxonomy in attacks that actually work: [simonwillison.net/tags/prompt-injection](https://simonwillison.net/tags/prompt-injection/)
    
    **Skill being learned:** orchestration as a state machine. The reason to use LangGraph rather than a chain is retries, branching and interrupts. If your graph is linear, you did not need the framework and an interviewer will ask why you used it.
    

---

# Day 5 — Triage node v0, validator environment

## Mouheb (AI) — the first real agent node

- [ ]  Implement the triage node: retrieve top-k ATT&CK and Sigma context, build the prompt, force structured output via tool-use schema, parse into `TriageVerdict`.
- [ ]  **Pass the alert as structured fields, not a rendered text blob.** Keep `untrusted_fields` content in clearly delimited, separately labeled sections from the first version. You are not building the defense yet, only the seam it will attach to.
- [ ]  Handle schema-invalid output explicitly: one retry with the validation error fed back, then fail loudly. Never silently coerce.
- [ ]  Run it on 20 golden alerts and read every output by hand. You are looking for failure *shapes*, not a score.

## Partner (Security) — get Zircolite actually running

<aside>
⏱️

This is scheduled on Day 5 rather than Week 3 for one reason: tooling around EVTX and Sigma backends is fiddly and will take longer than you expect. Discovering that in Week 3, when the repair loop depends on it, is how projects die.

</aside>

- [ ]  Install `sigma-cli` with the relevant pySigma backend. Compile one existing SigmaHQ rule successfully.
- [ ]  Get Zircolite running against one labeled EVTX file from the corpus.
- [ ]  End-to-end proof: take a rule you *know* should fire on a known dataset, run it, confirm the hit count matches what you expect. Write down the exact command sequence in `docs/validation-setup.md` so Mouheb can reproduce it without asking.
- [ ]  Split the corpus: `data/golden/` for triage evals, `data/validation/` held out for rule validation. Document the split rule. **No dataset appears in both.** Write the leakage check as a test.

<aside>
✅

**Checkpoint Day 5.** Triage returns a schema-valid `TriageVerdict` on 20 of 20 alerts with no parse failures. Zircolite runs a known-good rule and reports the expected hit count. The leakage test passes.

</aside>

- **Resources for Day 5**
    - Zircolite, Sigma rules against EVTX without a SIEM: [github.com/wagga40/Zircolite](https://github.com/wagga40/Zircolite)
    - sigma-cli and pySigma backends: [github.com/SigmaHQ/sigma-cli](https://github.com/SigmaHQ/sigma-cli) and [github.com/SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma)
    - Claude tool use for guaranteed-shape structured output: [docs.claude.com tool use](https://docs.claude.com/en/docs/agents-and-tools/tool-use/overview)
    - Microsoft's spotlighting paper, the technique you will implement in Week 4 — read it now so today's prompt structure does not fight it later: search "Defending Against Indirect Prompt Injection Attacks With Spotlighting" on arXiv
    
    **Skill being learned:** structured output under adversarial input, and treating tool setup as a first-class risk rather than an afterthought.
    

---

# Day 6 — Enrichment and the first honest ASR number

## Mouheb (AI) — tools, caching, routing

- [ ]  Implement two enrichment tools: NVD CVE lookup and an [abuse.ch](http://abuse.ch) IOC lookup (ThreatFox or URLhaus).
- [ ]  **Cache every response in Postgres.** NVD is rate-limited and slow; without a cache your eval runs on Day 7 will take hours and you will start skipping them.
- [ ]  Tool allow-list from the start: the agent can call exactly these two, and a call to anything else raises. Cheap now, and it is a real mitigation you get to cite in Week 4.
- [ ]  Two-tier routing: Haiku on the first pass, escalate to Sonnet when confidence is below threshold or technique assignment is ambiguous. Log which tier ran, token counts and cost to Langfuse.

## Partner (Security) — attack the half-built agent

- [ ]  Build `injection/runner.py`: take an `InjectionCase`, embed the payload into the named field of a real benign alert, run the pipeline, evaluate the success signal, write a result row.
- [ ]  Implement the first 10 payloads from the taxonomy, spread across at least three categories.
- [ ]  Run them. Record the result in `results/asr-day6.json`.

<aside>
📊

Expect a bad number. A pipeline with no defenses and an unstructured prompt commonly sits somewhere north of 50 percent attack success. **That is the point.** This ugly number is the left-hand bar of the before-and-after chart that is the entire differentiator of the project. Getting it on Day 6 rather than Week 4 also means that if the schedule slips, the differentiator already exists.

</aside>

<aside>
✅

**Checkpoint Day 6.** A Langfuse trace shows a full triage run with tool calls, tier routing and cost per alert. `results/asr-day6.json` exists with a real number in it from at least 10 payloads.

</aside>

- **Resources for Day 6**
    - NVD API 2.0, read the rate limits section before writing the client: [nvd.nist.gov/developers/vulnerabilities](https://nvd.nist.gov/developers/vulnerabilities)
    - ThreatFox API: [threatfox.abuse.ch/api](https://threatfox.abuse.ch/api/)
    - Claude models and pricing, for the routing threshold maths: [docs.claude.com models overview](https://docs.claude.com/en/docs/about-claude/models/overview)
    - Langfuse cost tracking and custom scores: [langfuse.com/docs/scores](https://langfuse.com/docs)
    - OWASP LLM01 prompt injection, re-read now that you are actually writing payloads: [genai.owasp.org/llm-top-10](https://genai.owasp.org/llm-top-10/)
    
    **Skill being learned (Mouheb):** cost and latency engineering in a multi-model pipeline. **Skill being learned (Partner):** red teaming an AI system through data rather than through the prompt box — the attack surface almost nobody tests.
    

---

# Day 7 — Evals, baseline, and the retro

## Mouheb (AI) — the eval runner

- [ ]  Build `evals/run.py`: load `golden-v1`, run N named configs, write `results/<config>.json`, render charts to `results/charts/`.
- [ ]  Three configs for the baseline: **single-prompt** (no retrieval, no tools), **RAG only**, **RAG plus tools**.
- [ ]  Every run records model, prompt hash, git SHA, timestamp. A result you cannot reproduce is not a result.

## Partner (Security) — the scorers

- [ ]  Build `evals/scorers.py`, implementing the metrics as the labeling guide defines them:
    - Triage accuracy (three-class)
    - Technique precision and recall with your partial-credit rules
    - Hallucinated-IOC rate: any IOC in `ioc_refs` not present anywhere in the input event JSON. A set difference, not a judgement.
    - Schema validity rate
    - Cost per alert and p95 latency
- [ ]  Unit-test every scorer with a hand-built example where you know the right answer. A wrong scorer produces confident wrong numbers for three weeks.

## Together — evening, approx. 2h

- [ ]  Run the baseline across the three configs. Look at the chart together.
- [ ]  **Read 10 failures out loud** and sort each into one of four buckets: retrieval miss, reasoning error, schema error, label error.
- [ ]  If more than two land in *label error*, stop and fix the labeling guide. That is a finding, not an embarrassment.
- [ ]  Write `docs/week1-retro.md`: what took longer than planned, what you are cutting, what moves to Week 2.

<aside>
🏁

**Week 1 gate.** You can say three numbers out loud without looking them up: triage accuracy on the baseline, technique F1, and Day 6 attack success rate. The baseline chart is in the README. If any of the three is missing, Week 2 does not start — spend Day 8 finishing Week 1 instead.

</aside>

- **Resources for Day 7**
    - Hamel Husain, "Your AI Product Needs Evals" — the best free writing on this and worth reading twice: [hamel.dev/blog/posts/evals](https://hamel.dev/blog/posts/evals/)
    - Anthropic on building evaluations: [docs.claude.com evals guide](https://docs.claude.com/en/docs/test-and-evaluate/develop-tests)
    - pytest parametrize, for testing the scorers cleanly: [docs.pytest.org parametrize](https://docs.pytest.org/en/stable/how-to/parametrize.html)
    - scikit-learn precision/recall definitions, to make sure you use the right averaging for multi-label: [scikit-learn metrics](https://scikit-learn.org/stable/modules/model_evaluation.html)
    
    **Skill being learned:** eval-driven development. From Day 7 onward every change is justified by a number rather than a feeling. This is the single most valuable habit in the project and the one hiring managers ask about.
    

---

# Things not to do this week

- [ ]  Do not build a frontend. Not a small one. Streamlit in Week 4, nothing before.
- [ ]  Do not self-host Langfuse. Free cloud tier, move on.
- [ ]  Do not deploy to AWS. That is Week 3, and only after the loop works locally.
- [ ]  Do not build an Active Directory lab. Replay labeled telemetry.
- [ ]  Do not normalize all four telemetry sources. Windows Sysmon this week, everything else later.
- [ ]  Do not tune prompts before Day 7. You have no way to tell whether a change helped, so you are guessing and calling it work.
- [ ]  Do not let either person go two days without merging. The integration debt compounds faster than you think.

---

# Week 1 deliverables, in one list

| Artifact | Owner | Due |
| --- | --- | --- |
| `schemas.py`, tagged `v0.1-contracts` | Joint | Day 1 |
| `labeling-guide.md` | Partner | Day 2 |
| Sysmon normalizer plus fixtures | Mouheb | Day 2 |
| Hybrid retrieval, recall at 5 measured | Mouheb | Day 3 |
| `threat-model.md` | Partner | Day 3 |
| Golden set, tagged `golden-v1` | Partner | Day 4 (hard gate) |
| LangGraph skeleton with tracing | Mouheb | Day 4 |
| Triage node v0 | Mouheb | Day 5 |
| Zircolite validated, leakage test | Partner | Day 5 |
| Enrichment tools, caching, routing | Mouheb | Day 6 |
| Injection runner, first ASR number | Partner | Day 6 |
| Eval runner and baseline charts | Mouheb | Day 7 |
| Scorers with unit tests | Partner | Day 7 |
| `week1-retro.md` | Joint | Day 7 |