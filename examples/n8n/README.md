# FedRAMP-Auto + n8n

Turn scan results into work: an n8n workflow that receives each scan from
`fedramp-auto` and

- **posts a Slack summary** when anything changed (coverage, new or resolved gaps),
- **opens a GitHub issue** for each new critical/high gap, with the risk, the fix and the snippet,
- **closes that issue** when a later scan no longer reports the gap.

```
fedramp-auto scan --webhook
  └─► Scan webhook ─► Verify signature ─► Respond (202 / 401) ─► Accept scan ─┬─► Slack summary ─► Post to Slack
                                                                              ├─► New gaps ─► Open GitHub issue
                                                                              └─► Resolved gaps ─► Find open issue ─► Match issue ─► Close GitHub issue
```

The scanner gets its answer before anything is sent to Slack or GitHub: **202**
if the signature checks out, **401** (with the reason) if it doesn't. A rejected
request shows as `Webhook not delivered: ... HTTP 401` in the scanner and as a
failed execution in n8n, and never reaches the Slack or GitHub nodes.

"New" and "resolved" are relative to the previous scan of the same directory and
baseline (from `output/history/`), so a nightly scan of an unchanged repo is quiet.

## What leaves your machine

The webhook carries KSI IDs, titles, severities, missing NIST controls, coverage,
remediation text and snippets, and the scanned directory's name. Resource names,
file paths and your infrastructure code are **not** sent. Requests are signed with
HMAC-SHA256 so n8n ignores anything that didn't come from your scanner.

n8n is self-hosted here, so the data stays on infrastructure you control until it
reaches GitHub or Slack.

## Setup

**1. Start n8n** (needs Docker)

```bash
cd examples/n8n
cp .env.example .env
# set FEDRAMP_WEBHOOK_SECRET (openssl rand -hex 32), FEDRAMP_GITHUB_REPO, FEDRAMP_SLACK_WEBHOOK_URL
docker compose up -d
```

Open http://localhost:5678 and create the owner account.

**2. Import the workflow**

Either *Workflows → Import from File → `fedramp-gap-alerts.json`*, or:

```bash
docker compose exec n8n n8n import:workflow --input=/workflows/fedramp-gap-alerts.json
```

**3. Add a GitHub credential** (skip if you only want Slack)

Create a *GitHub API* credential with a fine-grained token that has **Issues:
read and write** on the repo, then select it in *Open GitHub issue*, *Find open
issue* and *Close GitHub issue*.

**4. Activate the workflow** (toggle top right). The production URL is

```
http://localhost:5678/webhook/fedramp-auto
```

While editing, *Test workflow* listens on `/webhook-test/fedramp-auto` instead.

**5. Scan**

```bash
export FEDRAMP_WEBHOOK_URL=http://localhost:5678/webhook/fedramp-auto
export FEDRAMP_WEBHOOK_SECRET=<same value as in .env>
fedramp-auto scan ./infra --no-llm
```

Or send a result you already have:

```bash
fedramp-auto notify ./output/scan_result.json
```

### Without Docker

n8n also runs on Node.js 20 or 22:

```bash
export N8N_BLOCK_ENV_ACCESS_IN_NODE=false NODE_FUNCTION_ALLOW_BUILTIN=crypto
export FEDRAMP_WEBHOOK_SECRET=... FEDRAMP_GITHUB_REPO=owner/repo FEDRAMP_SLACK_WEBHOOK_URL=...
npx n8n import:workflow --input=fedramp-gap-alerts.json
npx n8n start
```

If you change `N8N_PORT` to 5679, also set `N8N_RUNNERS_BROKER_PORT` to something
else: n8n's task broker uses 5679 by default and will answer webhooks with
`Cannot POST`.

## From GitHub Actions

GitHub-hosted runners can't reach `localhost`. Expose n8n over HTTPS (reverse
proxy, Cloudflare Tunnel, or n8n Cloud), set `WEBHOOK_URL` in `.env`, and store
the URL and secret as repository secrets:

```yaml
- run: fedramp-auto scan infra --no-llm || [ $? -eq 2 ]
  env:
    FEDRAMP_WEBHOOK_URL: ${{ secrets.FEDRAMP_WEBHOOK_URL }}
    FEDRAMP_WEBHOOK_SECRET: ${{ secrets.FEDRAMP_WEBHOOK_SECRET }}
```

The payload then includes the repository, commit and run URL, and issues link back
to the run. Note that each runner starts with an empty `output/history/`, so
restore it with `actions/cache` (or a previous artifact) if you want new/resolved
tracking across runs; otherwise every open gap counts as new.

## Settings

| Variable | Default | Used for |
|----------|---------|----------|
| `FEDRAMP_WEBHOOK_SECRET` | required | Signature check (same value on both sides) |
| `FEDRAMP_ALLOW_UNSIGNED` | unset | `true` skips the check (local testing only) |
| `FEDRAMP_GITHUB_REPO` | empty | `owner/repo` for issues; empty disables GitHub |
| `FEDRAMP_ISSUE_SEVERITIES` | `critical,high` | Which new gaps get an issue |
| `FEDRAMP_SLACK_WEBHOOK_URL` | empty | Slack incoming webhook; empty disables Slack |

## Payload

`POST` with `Content-Type: application/json`,
`X-FedRAMP-Auto-Event: fedramp_auto.scan.completed` and
`X-FedRAMP-Auto-Signature: sha256=<HMAC of the raw body>`. See
[`sample-payload.json`](sample-payload.json).

To verify in your own receiver, compute HMAC-SHA256 over the **raw** request bytes,
not re-serialized JSON, and compare in constant time.

## Troubleshooting

- **401 `Raw body missing`**: open *Scan webhook → Options* and turn on *Raw Body*.
- **401 `Bad or missing X-FedRAMP-Auto-Signature`**: the secret differs between `.env` and `FEDRAMP_WEBHOOK_SECRET` in the scanner's environment.
- **`require` of `crypto` is not allowed**: `NODE_FUNCTION_ALLOW_BUILTIN=crypto` isn't reaching n8n (check `docker compose config`).
- **`$env` access denied**: set `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`, as the compose file does.
- **Webhook 404**: the workflow isn't active, or you're using `/webhook-test/` without clicking *Test workflow*.
