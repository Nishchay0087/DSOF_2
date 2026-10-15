# Honeypot behavior

The running FastAPI application manages three local services:

| Service | Default port | Protocol |
|---|---:|---|
| Web application | 8081 | HTTP/1.0 and HTTP/1.1 |
| SSH virtual shell | 2222 | Actual SSH transport through Paramiko |
| Database emulator | 3307 | Documented plaintext line protocol |

All bind to 127.0.0.1 by default. No payload, command or query executes on the
host. Limits bound concurrent connections, total session time, idle time,
message size and interaction count. Deployment is idempotent and verified
with an internal authenticated protocol probe before being marked listening.
Internal health probes never create attacker engagement records.

The SSH service accepts password authentication into a fictional virtual shell.
It records usernames, a deployment-keyed credential fingerprint and bounded
commands. Raw passwords are not retained. Forwarding and SFTP are disabled.
Commands such as `whoami`, `id`, `pwd`, `ls` and `cat /etc/passwd` return fixed
fictional text; other commands receive an unavailable response. The private
SSH host key persists beside the database. The legacy direct `Orchestrator`
constructor defaults to a line emulator for compatibility tests; the running
engine explicitly selects SSH transport.

The database line protocol supports HELP, AUTH, TABLES, SELECT and QUIT. It
never parses or executes SQL against a database. HTTP services expose static
landing, login, search and restricted pages, recording actual request actions.
Request bodies/query strings are not stored in raw form by the web honeypot.

Sessions are linked using an explicitly registered test UUID or the most recent
live alert with the same source and deployment within five minutes. Other
connections remain unattributed. IP attribution is a heuristic, not identity.
Only completed, attributed live sessions from newly profiled detections train
strategy feedback. Manual listener starts do not forge detection records.

A deployed listener only receives new connections addressed to its port. No
firewall rule, transparent redirection or route modification is performed.
On shutdown sockets close, active sessions are marked interrupted and restart
recovery does not count process downtime as engagement.
