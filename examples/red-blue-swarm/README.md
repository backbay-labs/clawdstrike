# Red/Blue Swarm Example

Red team agents attempt malicious actions while blue team monitors the hushd SSE event stream for violations in real-time.

## Architecture

```
┌──────────────┐                    ┌────────┐
│  red-recon   │─── POST /check ──▶│        │──── SSE ────▶┌───────────┐
│  red-exfil   │─── POST /check ──▶│ hushd  │──── SSE ────▶│ Blue Team │
│  red-persist │─── POST /check ──▶│        │──── SSE ────▶│ Listener  │
└──────────────┘                    └────────┘              └───────────┘
```

## Red Team Agents

| Agent        | Tactics                                         |
|--------------|------------------------------------------------|
| red-recon    | SSH keys, /etc/passwd, AWS creds, egress, shell |
| red-exfil    | pastebin, transfer.sh, AWS key leak, curl pipe  |
| red-persist  | crontab, bashrc, SUID, deploy malicious image   |

## Prerequisites

```bash
cargo run -p hushd -- --ruleset strict
```

## Run

```bash
npm install
npx tsx index.ts
```

## Expected Output

All red team actions are blocked with 100% detection rate. Blue team SSE listener captures every violation with agent attribution.
