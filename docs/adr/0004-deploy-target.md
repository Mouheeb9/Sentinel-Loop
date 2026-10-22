# ADR 0004: Deploy target for the Week 4 demo

- **Status:** Proposed (Mouadh to review)
- **Date:** 2026-10-22
- **Decision by:** Mouheb + Mouadh (to agree on Day 22)
- **Written by:** Mouheb
- **Code:** none yet (`docker-compose.yml` runs Postgres only; no app service, no dashboard)

## Context

The original plan (Week 1) was AWS ECS Fargate + RDS + GuardDuty from Week 3. We are about 10
days behind, and three facts make a cloud deploy worth less than it was:

1. **The model is the bottleneck, not the server.** Triage and rule generation run on free
   OpenRouter models at 50 requests/day, shared by both of us. A public endpoint that calls the
   model would use up the day's eval budget after a handful of visitors, and anyone could spend
   it.
2. **Nothing serves traffic yet.** There is no API service and no dashboard: the pipeline is a
   CLI (`sentinel.run`, `evals.*`) plus Postgres (pgvector, 697 techniques + 3,144 Sigma rules,
   ~12 MB of vectors). The demo needs a viewer for stored results more than a server.
3. **Raw data stays local.** `data/raw/` (637 MB of captures) is gitignored. The validator needs
   it for the noise check, and CI already skips that part.

What the demo has to show: alert -> triage verdict (+ Langfuse trace) -> generated rule ->
validator report -> PR. All of it already exists as stored results and links.

> Same reasoning as not exposing a SOC tool to the internet just to show it works: you put the
> read-only view where people can see it and keep the part that holds keys and budget inside.

## Options considered

Monthly prices are AWS us-east-1 on-demand list prices as we know them; **check them in the AWS
pricing calculator before the decision** (they are the reason for the choice, so they must be
right).

| option | what runs where | cost / month | for | against |
|---|---|---|---|---|
| A. ECS Fargate + RDS (original plan) | app container (0.5 vCPU, 1 GB) + RDS Postgres db.t4g.micro + ALB | ~$18 Fargate + ~$14 RDS (with 20 GB) + ~$16 ALB + ~$4 public IPv4 = **~$50** | the "cloud" line on the CV; IaC practice | the most money and setup time; still can't call the model publicly (quota); new IAM/network attack surface to secure in the hardening week |
| B. Free host for a read-only dashboard | Streamlit on a free tier (e.g. Hugging Face Spaces CPU) reading committed results; no model calls, no DB | **$0** | public link for the README; no keys on the host | free tiers sleep and change terms; shows stored runs only |
| C. Local docker-compose + recorded demo | everything on a laptop: Postgres + pipeline + dashboard; 3-minute video | **$0** | the full live loop on camera; nothing to secure online | no link to click; "works on my machine" unless the compose file is complete |

## Decision (proposed)

**B + C:** a complete `docker-compose.yml` (Postgres + app + Streamlit) that runs the live loop
locally for the video, and the same Streamlit app on a free host in **read-only mode** (stored
results, no model key, no database) for the README link.

A (ECS + RDS) is not built. If wanted for the CV, a short "how this maps to ECS + RDS" section in
the README (task definition, RDS with pgvector, secrets in SSM) is honest and costs nothing.

## Consequences

- Week 4 deploy work is small: an app service in compose, a Streamlit app, one free-host deploy.
  The time goes to hardening and before/after numbers instead.
- The public demo can't be used to spend our quota or reach our keys: it has neither.
- We give up a running cloud deploy. Anyone asking "did you deploy it?" gets B (public,
  read-only) and C (full loop on video), and the reason (quota + cost) in this ADR.
- The read-only app must not show raw attacker-written strings as HTML (the dashboard renders
  event values: escape them, same rule as PR text in `sentinel.publish`).

## Revisit when

- We get a paid model key or a quota that can take public traffic: then A (or a single
  container on a cheap VM) becomes worth it.
- The free host's terms or sleep behavior break the README link.
