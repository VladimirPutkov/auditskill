# DEPLOY — AuditSkill runbook

> Status (2026-07-08): deployed and live at **https://auditskill.up.railway.app**
> (GitHub → Railway auto-deploy from `main`). This file is the maintenance
> runbook: how to redeploy, verify, and what must stay true.

## Redeploy

Railway auto-deploys on push to `main`:

```powershell
cd "C:\Users\putko\Desktop\NANDAHACK Audit\auditskill"
pytest -q          # must be green before any push
git add -A ; git commit -m "<change>" ; git push
```

Watch the Railway dashboard until the deploy is green and `/health` passes.

## Environment variables (Railway → Variables)

| Variable | Required | Notes |
|---|---|---|
| `AUDITSKILL_PRIVATE_KEY` | **Yes** | Base64 Ed25519 signing key. The public key is **derived from it** at runtime — `/verify` and `/.well-known` can never mismatch the signing key. |
| `AUDITSKILL_PUBLIC_KEY` | No | Fallback for verify-only deployments; ignored while the private key is set. |
| `AUDITSKILL_KEY_ID` | No | Defaults to `auditskill-2026-07`. |

Generate a fresh pair if ever needed: `python scripts/generate_keys.py`
(never commit key material; `.gitignore` already excludes `.env` and `data/*.db`).

## Post-deploy smoke test (run all five, in order)

```bash
curl https://auditskill.up.railway.app/health          # {"status":"ok"}
curl https://auditskill.up.railway.app/skill.md -I     # 200, text/markdown
curl "https://auditskill.up.railway.app/discover?mode=safe_static&limit=10"   # 200, ranked results
curl -X POST https://auditskill.up.railway.app/audit -H "Content-Type: application/json" \
  -d '{"skill_md":"# T\n\nD.\n\n## Base URL\nhttps://t.example.com\n\n## Endpoints\nGET /z","mode":"safe_static"}'
# → take .certificate from the response and POST it to /verify → {"valid": true}
```

Then the meta-demo (strongest judge argument):

```bash
curl -X POST https://auditskill.up.railway.app/audit -H "Content-Type: application/json" \
  -d '{"skill_url":"https://auditskill.up.railway.app/skill.md","mode":"safe_static"}'
# Expect: PASS_BASIC_AUDIT, security 100, 0 findings
```

## Keep-alive (required before judging)

Railway free tier sleeps idle containers; a judge's first call would hang.
Set up a free pinger (UptimeRobot / cron-job.org) hitting `GET /health` every 5 minutes.

## Registry submission (human step)

https://nandatown.projectnanda.org → skills → submit the hosted SKILL.md URL
(`https://auditskill.up.railway.app/skill.md`) + the GitHub repo link.
Only submit while `/health` responds reliably — dead links disqualify.
