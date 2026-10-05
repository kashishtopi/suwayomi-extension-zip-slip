# Suwayomi-Server: Unauthenticated Arbitrary File Write via Extension APK (Zip Slip)

## Description

Suwayomi-Server is a self-hosted manga server. When it installs an uploaded extension
APK, it extracts every zip entry whose name starts with `assets/` with no path
normalization and no containment check. An entry named `assets/../../<path>` passes the
only guard and escapes the extraction directory, writing an attacker-controlled file
anywhere the server can write. This leads to remote code execution (startup script,
cron, `authorized_keys`, or overwriting the loaded extension jar). The server ships with
`authMode=NONE`.

- Endpoint: `POST /api/v1/extension/install`
- Privilege: none (default `authMode=NONE`)

## Exploit

`poc.py` (standard library only) downloads a valid base APK, repackages it with a
traversal entry, and installs it.

```
python3 poc.py --url http://localhost:4567 --dest /tmp/suwa_pwned_zipslip
# verify on the host:
docker exec <suwayomi-container> cat /tmp/suwa_pwned_zipslip
```

The base must be a real extension APK and must be fully repackaged (an appended entry
lands after the APK signing block, which Java's `ZipInputStream` stops at). A benign
`assets/keep.txt` entry precedes the traversal entry so the `assets/` directory exists
on disk at open time.

## Disclaimer

This proof of concept is for authorized security testing and education only.
Test only systems that you own or have explicit permission to test. The author
takes no responsibility for misuse.
