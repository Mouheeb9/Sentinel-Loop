# Tools eval: a test set where the lookup decides the answer

- **Status:** v1 run 2026-11-21, hypothesis passed (see `docs/experiments.md`); B-clean fix open
- **Owners:** Mouadh (cases, IOCs, labels), Mouheb (harness, metrics, report); labels reviewed by both
- **Budget:** ~2-3 days, ~150 model calls (rag + rag-tools, 2 runs each, on 30 cases)

## Why

The dev split can't tell us whether the tools help. They fire on almost no dev alert (1 of 23 in
Week 2): our alerts are Windows endpoint events with few public IPs and no CVEs. So `rag-tools` on
dev is only a regression check ("tools on doesn't break triage"). To measure the tools we need
alerts whose right answer depends on what the lookup returns.

> Same as testing a SIEM's threat-intel enrichment: logs with no external IPs prove nothing. You
> replay traffic to a known-bad C2 and to a clean CDN, and check the alert changes.

## What the tools can look up (constraints from the code)

Read before building cases; a case outside these rules never gets a tool offered.

- `lookup_targets` (`src/sentinel/tools/__init__.py`) offers tools **only** if the alert has a
  **public IP** (network dst/src), a **public URL** (in a command line, parent command line or
  registry value) or a **CVE id** (same fields). No target -> no tool offered.
- **Not targets:** bare domains, file hashes, private/reserved IPs, reserved test domains
  (`example.com` ...), internal suffixes. A hash or bare-domain case would need a code change
  first (out of scope for v1).
- `check_args` refuses any lookup value that isn't one of those targets, so the model can't look
  up something the alert doesn't contain.
- Tool answers are cached in Postgres (`tool_cache`); `SENTINEL_TOOL_CACHE=frozen` reuses them
  forever. ThreatFox removes old IOCs, so the cache taken at build time **is** the ground truth.

## The cases (30)

**Design: counterfactual pairs.** Two alerts identical except for the looked-up value: one with a
value ThreatFox knows as malicious, one with a clean value. Without tools the model sees the same
alert twice and can get at most one of the pair right; with tools it can get both. This isolates
the lookup's effect from everything else in the alert.

| Group | n | Content | Gold label |
|---|---|---|---|
| A. IP pairs, bad | 8 | ambiguous process (browser, `svchost`, `curl`, `msedge`, signed updater) connecting to a public IP that ThreatFox lists as C2 | true_positive + technique (e.g. T1071.001) |
| A. IP pairs, clean | 8 | same events, IP of a big CDN / Microsoft / Google range | benign_noisy |
| B. URL pairs, bad | 4 | `powershell iwr` / `certutil -urlcache` / `bitsadmin` to a URL ThreatFox lists (payload delivery) | true_positive (T1105) |
| B. URL pairs, clean | 4 | same command to a vendor download URL | judgment call, see note |
| C. CVE, exploit-like | 3 | command line / registry naming a CVE in an exploit context (e.g. a PoC binary name, `CVE-2021-40444` doc lure) | true_positive |
| C. CVE, benign | 3 | CVE in a patch installer (`wusa.exe ... KB`), scanner or inventory log | benign_noisy |

Note on B-clean: `certutil -urlcache` to any URL is already suspicious (T1105 LOLBin). Pick
commands where the clean version is really benign (`bitsadmin` by a signed updater, `iwr` by an
admin script path), or drop the pair. Mouadh decides, and writes why in the rationale.

Rules for building them (Mouadh):
1. **Real IOCs, taken from ThreatFox at build time**, and confirmed by one live lookup through
   our own tool (so the cache holds the answer). Record IOC, ThreatFox id and date in the label
   rationale.
2. **Realistic events:** start from a real golden event of the same type (Sysmon 1 / 3 / 13) and
   change only what the case needs. No template the model can pattern-match ("C2_IP_HERE").
3. **Nothing in the alert says the answer:** no "malware" in file names, no comments. The
   lookup must be the only new information.
4. **Labels** in the same format as `data/golden/labels.jsonl`, `labeler: Mouadh` then reviewed ->
   `Mouheb+Partner`.

## Where the files go (don't break the dev fingerprint)

`evals.run` hashes `data/golden/day*_candidates.json` into every row's fingerprint
(`alerts_sha`). Adding the tools cases there would make every stored dev result stale and turn
the CI gate red. So keep them separate:

- `data/tools-eval/candidates.json` (alerts, same schema as the golden candidates)
- `data/tools-eval/labels.jsonl` (labels)
- `data/tools-eval/cache.json`: export of the `tool_cache` rows for these IOCs, so the set can be
  rebuilt on another machine and the answers never drift.
- `evals.run --set tools` (new flag, Mouheb): loads that set instead of the golden one, writes to
  `results/<run>/tools/`, own fingerprint.

## Metrics

Per config (`rag` = tools off, `rag-tools` = tools on), same 30 cases:

| Metric | What it answers |
|---|---|
| **Pair accuracy** (both alerts of a pair right) | does the lookup change the verdict the right way? Main number |
| Verdict accuracy, attack recall, technique F1 | the usual scores, comparable with dev |
| **Lookup recall** | of the cases with a target, how often the model called the tool |
| Lookups on clean cases that flipped the verdict | does a clean lookup ever push to true_positive? (should be 0) |
| Refused calls (`check_args`) | is the model trying to look up things that aren't targets? |

Expected without tools: pair accuracy near 0 (two alerts that differ only by an IP get the same
verdict) and per-alert accuracy near .50. That is the floor the tools have to beat.

## Hypothesis (written before any run)

**rag-tools pair accuracy >= .60 (8 of 12 pairs, groups A+B) and >= rag + .40**, in both runs, **and** no clean
case flipped to true_positive by a lookup. If it fails: read the traces (did it call the tool? did
it read the answer?) before changing anything; one change, one re-run.

## Steps

| # | Who | What | Done when |
|---|---|---|---|
| 1 | Mouadh | Pick 12 IOCs (8 IP, 4 URL) from ThreatFox + 12 clean twins + 6 CVE cases; write the events | `candidates.json` + `labels.jsonl` |
| 2 | Mouheb | `--set tools` in `evals.run`, cache export/import, pair metrics in the scorer + tests | tests green, stub run 30/30 |
| 3 | Both | Review labels together (Day 2-style review), live lookup on each IOC to fill the cache | labels `Mouheb+Partner`, `cache.json` committed |
| 4 | Mouheb | Runs: `rag` x2, `rag-tools` x2, `--set tools`, frozen cache | 4 result files |
| 5 | Both | Results + verdict on the hypothesis in `docs/experiments.md`; README line | PR merged |

## Out of scope (v1)

Hash and bare-domain lookups (need `lookup_targets` changes and their own injection tests), cloud
alerts, new tools. Injection through tool results is already covered by the `tool_hijack`
payloads in the injection set.
