"""Report writer: JSON for tools, Markdown for humans. Every target lists its evidence."""
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path


def write_reports(res, build, cfg, outdir):
    outdir = Path(outdir)
    doc = {"generated": datetime.now().isoformat(timespec="seconds"),
           "inputs": {"old_mod": cfg.old_mod, "old_official": cfg.old_official, "new_official": cfg.new_official},
           "summary": res.summary, "native_targets": [asdict(t) for t in res.native],
           "file_targets": [asdict(f) for f in res.files], "unhandled": res.issues,
           "checks": [asdict(c) for c in build.checks], "outputs": build.outputs, "result": build.message}
    jp, mp = outdir / "report.json", outdir / "report.md"
    jp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    L = ["# APK porting report", "", f"Generated {doc['generated']}", "",
         f"- Old modded: `{cfg.old_mod}`", f"- Old official: `{cfg.old_official}`", f"- New official: `{cfg.new_official}`", "",
         "## Native modifications", ""]
    for t in res.native:
        L += [f"### {t.id} {t.old_name}: **{t.status}** ({t.confidence:.1f}%)",
              f"- `{t.path}` old `{t.old_vaddr:#x}` -> new `{t.new_vaddr:#x}` ({t.new_name})",
              f"- {len(t.words)} instruction word(s) changed: " + ", ".join(f"#{w.index} {w.old_word:#010x}->{w.new_word:#010x}" for w in t.words[:12])]
        if t.message:
            L.append(f"- {t.message}")
        L += [f"- evidence: {e}" for e in t.evidence] + [""]
    L += ["## File modifications", ""]
    for f in res.files:
        L += [f"- {f.id} {f.action} `{f.path}`: **{f.status}** ({f.confidence:.0f}%) {f.message}"]
    if res.issues:
        L += ["", "## Requires manual intervention", ""] + [f"- {i}" for i in res.issues]
    L += ["", "## Verification", ""] + [f"- {'PASS' if c.ok else 'FAIL'} {c.name} {c.detail}" for c in build.checks]
    L += ["", "## Output", ""] + [f"- `{o}`" for o in build.outputs] + ["", build.message, ""]
    mp.write_text("\n".join(L), encoding="utf-8")
    return jp, mp
