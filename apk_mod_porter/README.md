# APK Mod Porting Tool

Ports binary modifications from an old modded APK to a newer official APK, with evidence for every decision.

## Inputs
1. Old modded APK
2. Old official APK (the version the mod was built on). Needed to tell mod edits apart from normal version changes.
3. New official APK
4. Optional: Il2CppDumper `script.json` for the old and new builds (strong method-name signal)

Split bundles (.apks/.xapk/.zip of APKs) are supported.

## Run
    pip install -r requirements.txt
    python main.py                       # GUI
    python main.py --cli --old-mod m.apk --old-official o.apk --new-official n.apk --out output
    python -m unittest discover -s tests # synthetic end-to-end tests

Signing needs a JDK and Android build-tools (`apksigner`, found via PATH, ANDROID_HOME or ANDROID_SDK_ROOT).
Without them the tool writes an aligned `*_UNSIGNED.apk`. Output is signed with a different key than the
official app, so the official app must be uninstalled first.

## Layout
    main.py                    entry point (GUI or CLI)
    apkporter/apk_manager.py   open/split handling, rebuild, in-process alignment, signing
    apkporter/diff_engine.py   file-level comparison
    apkporter/elf.py           ELF64 sections, function boundaries (.eh_frame_hdr, prologue fallback)
    apkporter/aarch64.py       instruction normalisation, BL targets
    apkporter/il2cpp.py        global-metadata.dat parsing, symbol map loading
    apkporter/matching.py      fingerprints, candidate search, scoring, instruction mapping
    apkporter/patch_engine.py  derive, plan and apply patches; JSON patch export
    apkporter/verification.py  integrity, alignment, "only planned bytes changed", apksigner verify
    apkporter/pipeline.py      analyse and build workflows
    apkporter/report.py        report.json / report.md
    apkporter/gui.py           Tkinter GUI with live log

## Safety rules
- A target is applied only at or above the auto-apply threshold; review-level matches need an explicit tick.
- Expected original bytes are checked before every write.
- PC-relative replacement instructions are refused (cannot be relocated safely).
- If any target is unresolved the build stops with "Patch target could not be reliably identified.
  Manual analysis required." unless partial port is enabled.

## Transplant mode (runtime-hook mods)
For mods that resolve their targets by name at runtime (IL2CPP API) instead of patching game code, use:

    python main.py --transplant --old-mod mod.apk --new-official new_merged.apk --apktool apktool.jar --out output

It checks the mod's target names against the new `global-metadata.dat`, inserts the startup call into
`UnityPlayerActivity.onCreate` (smali round trip on that one dex only), adds the menu dex, the native library,
the overlay permission and the service entry (append-only manifest edit), then aligns, signs and verifies that
only the planned files changed. Needs Java, apktool.jar, and apksigner for signing. `new_merged.apk` must be a
single APK (merge XAPK splits first).

The GUI has a mode switch ("Binary patch port" or "Transplant runtime-hook mod"). In transplant mode only the
modded APK, new official APK, apktool.jar and output folder are used.
