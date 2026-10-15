# Troubleshooting

Run commands from the workspace with `.\.venv\Scripts\python.exe` to avoid using an unrelated Python installation. Do not edit the saved model or CSV to make a check pass.

| Symptom | Check and remedy |
|---|---|
| Web page loads but collector stopped/failed | Read `/api/collector`; the web process and capture are independent. Run `python -m dsof check`. Use its exact device ID. |
| Missing Npcap/backend | Install Npcap from its official vendor; confirm `Get-Service npcap`, restart PowerShell, rerun `check`. Python Scapy alone is insufficient on Windows. |
| Access denied opening capture | Npcap may be restricted to administrators. Use elevated PowerShell if the installed policy requires it; do not disable security software. |
| Invalid interface | Copy an exact ID from `check` into `.env` `DSOF_INTERFACES`. Adapter IDs can change. Loopback is required for fresh local tests. |
| LAN traffic absent | Default scope is loopback endpoints only. Explicitly select your authorized physical interface to observe that network. Capture sees only traffic visible to selected devices, not the whole network. |
| Model unavailable | Run `validate`; check required model/schema/label files and install pinned dependencies. Hash mismatch requires investigating the original file, not updating the baseline to hide modification. |
| Strong probability but wrong class | Live training parity is unresolved; inspect feature conventions and missing provenance. Do not adjust features or claim calibration. HTTP rules independently detect supported cleartext indicators. |
| Honeypot failed | Read deployment `error`. Check `Get-NetTCPConnection -LocalPort 8081` (or configured port). Choose unused distinct ports in `.env` and restart. A port conflict must not be labeled listening. |
| Duplicate instance | Stop the existing DSOF process with Ctrl+C. The OS releases its file lock on exit; a stale lock filename alone does not block restart. Do not delete a held file to bypass the lock. |
| No alert immediately | Wait for the configured flow idle/lifetime limits; check collector packets/drops, exclusions, model output and HTTP inspection limits. A benign request should normally yield a flow without a rule alert. |
| Alert but no session/DSI | Detection does not redirect traffic. Connect to the verified honeypot address and port; `fresh_test.py` performs and verifies this step. Health probes do not count. |
| Encrypted/chunked HTTP | HTTPS payloads, HTTP/2 and chunked/ambiguous/oversized streams are explicitly unsupported. Numeric model features may still be extracted. Do not claim payload inspection. |
| Dashboard disconnected/stale | The page marks stale status after five seconds without snapshots, retries Socket.IO, and restores backend state after reconnect/refresh. Check web server, browser console and `data/dsof.log`. |
| 401 mutation | Use the local `data/control.token` via Authorization header. The browser intentionally has no secret/control UI. |
| SQLite failure | Confirm `data/` is writable and disk space is available. Do not remove an open database/WAL. Stop DSOF before copying backups. FK/schema-version failures must be investigated, not ignored. |
| Test failure | Nonzero fresh-test exit means a required stage failed. Preserve printed IDs/logs. Replay is not an acceptable substitute for a failed fresh-capture check. |

`data/dsof.log` rotates at 2 MB with three backups. SQLite stores UTC timestamps, minimal rule evidence and action metadata; packet payloads are bounded in memory and not stored wholesale. Retention runs at startup/hourly, preserving parents needed by retained child records; disk use is not a guaranteed fixed-size cap. No stress-tested throughput guarantee is made.

## Local collector control

For a deliberate stop/restart test while the web server remains running:

```powershell
$dsofToken = (Get-Content .\data\control.token -Raw).Trim()
$dsofHeaders = @{ Authorization = "Bearer $dsofToken" }
Invoke-RestMethod http://127.0.0.1:5000/api/collector/control -Method Post -Headers $dsofHeaders -ContentType application/json -Body '{"action":"stop"}'
Invoke-RestMethod http://127.0.0.1:5000/api/collector/control -Method Post -Headers $dsofHeaders -ContentType application/json -Body '{"action":"start"}'
Remove-Variable dsofToken,dsofHeaders
```

Stopping collection can discard queued packets; `shutdown_discarded_packets` records this. Existing measured flow snapshots may finalize afterward. This control cannot fabricate packets, alerts or sessions.
