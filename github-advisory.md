# Advisory submission (Suwayomi/Suwayomi-Server security advisory, or MITRE if no CNA response)

## Title
Unauthenticated Arbitrary File Write via Extension APK (Zip Slip) Leading to RCE

## Affected products
- Ecosystem: Other (self-hosted application)
- Package name: Suwayomi/Suwayomi-Server
- Affected versions: current (tested at commit dba836b)
- Patched versions: (none at time of report)

## Severity
- CVSS v3.1: 9.8 (Critical)
- Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## CWE
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Zip Slip)

## CVE identifier
- Request a CVE

---

### Summary
`POST /api/v1/extension/install` accepts an uploaded extension APK and, during install, extracts
every zip entry whose name starts with `assets/` to `<extensionsRoot>/<name>_assets/<entry name>`
with no path normalization or containment check. An entry named `assets/../../.../<abs path>`
passes the only guard (`startsWith("assets/")`) and the `../` sequence writes an attacker
controlled file to an arbitrary path as the server process user, giving remote code execution.
The server defaults to `authMode=NONE` (unauthenticated) and uses a reflect-origin,
allow-credentials CORS policy (drive-by capable).

### Details
`Extension.extractAssetsFromApk` iterates the APK with `ZipInputStream` and, for each entry where
`zipEntry.name.startsWith("assets/") && !zipEntry.isDirectory`, computes
`assetFile = assetsFolder / zipEntry.name`, calls `createParentDirectories()`, and writes the
entry. `zipEntry.name` is never normalized or verified to remain within `assetsFolder`, so `../`
segments escape it. Extraction runs inside `prepareJarAndIcons` before the extension is validated
or loaded, so the write happens even if the extension ultimately fails to load. The install
endpoint performs no authentication in the default configuration.

### PoC
1. Take a valid Tachiyomi/Mihon extension APK (real `classes.dex` + manifest, versionName
   major.minor in 1.3-1.6, `tachiyomi.extension` feature, source-class metadata) so parsing and
   `dex2jar` succeed.
2. Repackage it (full rewrite, dropping the APK signing block so Java's `ZipInputStream` reads all
   entries) adding: a benign `assets/keep.txt` entry (so the literal `assets/` directory exists at
   open time), then an entry named
   `assets/../../../../../../../../../../../../tmp/suwa_pwned_zipslip` with the payload.
3. `POST /api/v1/extension/install` (unauthenticated), field `file`. Response HTTP 200.
4. On the host, `/tmp/suwa_pwned_zipslip` now exists with the attacker-controlled contents, owned
   by the Suwayomi process user, outside the extensions directory.

Verified on the current build (commit dba836b): the upload returned HTTP 200 and the file was
written outside the extensions directory with attacker-controlled contents. A self-contained PoC
is provided.

### Impact
Unauthenticated arbitrary file write as the server process, escaping the extensions directory.
This escalates to remote code execution (startup/cron script, `~/.ssh/authorized_keys`,
overwriting the loaded extension `.jar`). Full host compromise; default no-auth and permissive
CORS make it remotely and drive-by exploitable.

### Remediation
- Resolve each extracted asset against the assets root, normalize, and verify it still starts with
  the assets root; reject entries containing `..` or absolute paths.
- Authenticate the caller before extracting any uploaded package; change the default `authMode`
  away from `NONE` and restrict CORS (do not reflect arbitrary origins with credentials).
- Validate the uploaded extension (signature/allowlist) before extraction.

### Credit
Kashish Topiwala
