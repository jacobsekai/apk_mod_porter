#!/usr/bin/env python3
"""APK Mod Porting Tool. `python main.py` opens the GUI; `python main.py --cli ...` runs headless."""
import argparse
import sys

from apkporter import logutil
from apkporter.models import Config
from apkporter.pipeline import Pipeline


def cli(a):
    log = logutil.setup(logfile=a.log)
    cfg = Config(a.old_mod, a.old_official, a.new_official, a.out, a.symbols_old or "", a.symbols_new or "",
                 a.apply_threshold, a.review_threshold, a.apply_review, a.allow_partial, a.keystore or "")
    p = Pipeline(cfg, log)
    res = p.analyse()
    if a.analyse_only:
        return 0
    out = p.build(res)
    return 0 if out.ok else 1


def transplant(a):
    from apkporter import transplant as tp
    log = logutil.setup(logfile=a.log)
    try:
        tp.run(a.new_official, a.old_mod, a.out, a.apktool, log, a.keystore or "", menu_dex=a.menu_dex,
               allow_missing_names=a.allow_missing_names, custom_signer=a.apk_signer or "",
             custom_signer_args=a.apk_signer_args or "", old_official=a.old_official)
        return 0
    except tp.TransplantError as e:
        log.error(f"STOPPED: {e}")
        return 1


def certspoof(a):
    """Certificate-spoof pipeline: extract reference fingerprint, hook the target launcher
    activity, rebuild, align, sign (V2+V3), and auto-verify the fingerprint matches."""
    from apkporter import cert_spoof as cs
    log = logutil.setup(logfile=a.log)
    try:
        out = cs.run(a.reference_apk, a.target_apk, a.out, a.apktool, log, a.keystore or "",
                     ks_pass=a.ks_pass, ks_alias=a.ks_alias)
        print(f"cert spoof output: {out}")
        return 0
    except cs.CertSpoofError as e:
        log.error(f"STOPPED: {e}")
        return 1


def main():
    ap = argparse.ArgumentParser(description="Port binary modifications between app versions with evidence and safety checks")
    ap.add_argument("--cli", action="store_true")
    ap.add_argument("--old-mod"), ap.add_argument("--old-official"), ap.add_argument("--new-official")
    ap.add_argument("--symbols-old"), ap.add_argument("--symbols-new"), ap.add_argument("--keystore")
    ap.add_argument("--out", default="output"), ap.add_argument("--log")
    ap.add_argument("--apply-threshold", type=float, default=90.0)
    ap.add_argument("--review-threshold", type=float, default=70.0)
    ap.add_argument("--apply-review", action="store_true"), ap.add_argument("--allow-partial", action="store_true")
    ap.add_argument("--analyse-only", action="store_true")
    ap.add_argument("--transplant", action="store_true", help="carry a runtime-hook mod onto --new-official (uses --old-mod as the source and --old-official as its baseline)")
    ap.add_argument("--apktool", help="path to apktool.jar (needed for --transplant and --cert-spoof)")
    ap.add_argument("--menu-dex", default="classes6.dex"), ap.add_argument("--allow-missing-names", action="store_true")
    ap.add_argument("--apk-signer", help="optional custom APK signer executable or jar; supports {apk} and {out} placeholders")
    ap.add_argument("--apk-signer-args", help="extra args for the custom APK signer; useful for Uber APK Signer or Java jar flags")

    # --- certificate spoofing ---
    ap.add_argument("--cert-spoof", action="store_true",
                    help="inject a certificate-spoof hook into the target APK's launcher activity")
    ap.add_argument("--reference-apk", help="APK whose SHA-256 certificate fingerprint will be spoofed")
    ap.add_argument("--target-apk", help="APK to patch (decoded, hooked, aligned, signed V2+V3)")
    ap.add_argument("--ks-pass", default="android", help="keystore password (default: android)")
    ap.add_argument("--ks-alias", default="key0", help="keystore key alias (default: key0)")

    a = ap.parse_args()

    if a.cert_spoof:
        if not (a.reference_apk and a.target_apk and a.apktool):
            ap.error("--cert-spoof needs --reference-apk, --target-apk and --apktool")
        sys.exit(certspoof(a))
    if a.transplant:
        if not (a.old_mod and a.old_official and a.new_official and a.apktool):
            ap.error("--transplant needs --old-mod, --old-official, --new-official and --apktool")
        sys.exit(transplant(a))
    if a.cli:
        if not (a.old_mod and a.old_official and a.new_official):
            ap.error("--old-mod, --old-official and --new-official are required with --cli")
        sys.exit(cli(a))
    from apkporter.gui import main as gui
    gui()


if __name__ == "__main__":
    main()