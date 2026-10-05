"""
Minimal, dependency-free PDF builder for the remediation report.

Produces a real, downloadable multi-page PDF using only the standard library --
no reportlab/fpdf/weasyprint, so it works on any host. Uses the built-in
Helvetica fonts (always present in PDF viewers) with WinAnsi encoding, so
em-dashes and curly quotes render correctly.

Visual style matches the Guardian web dashboard: soft light background,
dark slate body text, a green accent for "held" items, a red accent for
confirmed vulnerabilities, colored status chips, left accent bars on each
scenario card, and a page footer.
"""
from __future__ import annotations

from typing import Any

PAGE_W, PAGE_H, MARGIN = 612, 792, 54
LINE_FACTOR = 1.5

# -- palette (0..1 RGB), matched to the web dashboard's light theme --
TEXT = (0.086, 0.129, 0.110)      # near-black slate body text
MUTED = (0.298, 0.361, 0.337)     # secondary/meta text
GREEN = (0.071, 0.573, 0.353)     # held / acid accent
GREEN_DK = (0.055, 0.478, 0.286)  # darker green for fix labels
RED = (0.812, 0.267, 0.298)       # vulnerable accent
AMBER = (0.722, 0.522, 0.031)     # category label
CARD_BG = (0.933, 0.949, 0.937)   # light card background
WHITE = (1.0, 1.0, 1.0)
LINE_GRAY = (0.855, 0.878, 0.867)


def _wrap(text: str, max_chars: int) -> list[str]:
    words = str(text).split()
    lines: list[str] = []
    cur = ""
    for w in words:
        while len(w) > max_chars:
            if cur:
                lines.append(cur); cur = ""
            lines.append(w[:max_chars]); w = w[max_chars:]
        if not cur:
            cur = w
        elif len(cur) + 1 + len(w) <= max_chars:
            cur += " " + w
        else:
            lines.append(cur); cur = w
    if cur:
        lines.append(cur)
    return lines or [""]


def _esc(s: str) -> str:
    s = str(s).encode("cp1252", "replace").decode("cp1252")
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_remediation_pdf(items: list[dict[str, Any]], run_id: str) -> bytes:
    """Full run report PDF -- every scenario that was executed, not just the
    confirmed vulnerabilities: what was attempted, what tool it targeted, the
    literal messages sent, the workflow's real replies, and the verdict --
    evidence + fix for a confirmed issue, or why the control held otherwise.

    `items` is the report's `readable_findings` list (see reporter.py). Also
    accepts the older {category, title, what_happened, fix, note} shape for
    backward compatibility, rendered as a confirmed-issue-only summary.
    """
    # Each page is a list of drawing ops:
    #   ("T", x, y, size, font, text, color)   -- text
    #   ("R", x, y, w, h, color)               -- filled rectangle
    pages: list[list[tuple]] = []
    cur: list[tuple] = []
    y = PAGE_H - MARGIN

    def new_page():
        nonlocal cur, y
        if cur:
            pages.append(cur)
        cur = []
        y = PAGE_H - MARGIN

    def rect(x, yy, w, h, color):
        cur.append(("R", x, yy, w, h, color))

    def hline(yy, color=LINE_GRAY, w=1.0):
        rect(MARGIN, yy, PAGE_W - 2 * MARGIN, w, color)

    def emit(text: str, size: int, font: str, max_chars: int,
             gap_before: float = 0.0, indent: float = 0.0, color=TEXT):
        nonlocal y
        first = True
        for chunk in _wrap(text, max_chars):
            step = size * LINE_FACTOR + (gap_before if first else 0.0)
            if y - step < MARGIN + 20:
                new_page()
            y -= step
            first = False
            cur.append(("T", MARGIN + indent, y, size, font, chunk, color))

    def emit_list(label: str, values: list, numbered: bool = False):
        if not values:
            return
        emit(label, 10, "F2", 95, gap_before=5, color=GREEN_DK)
        for n, v in enumerate(values, start=1):
            text = f"{n}. {v}" if numbered else f"• {v}"
            emit(text, 10.5, "F1", 92, indent=10)

    def status_chip(label: str, color, x, yy):
        """Small filled pill behind a short status word, drawn to the left
        of the item title line at its baseline."""
        w = 6.2 * len(label) + 14
        h = 15
        rect(x, yy - 3, w, h, color)
        cur.append(("T", x + 7, yy, 9.5, "F2", label, WHITE))
        return w

    is_readable_shape = bool(items) and "attack_objective" in items[0]

    # -- title band --
    emit("Guardian Evaluation Report", 21, "F2", 52, color=TEXT)
    if is_readable_shape:
        confirmed = sum(1 for it in items if it.get("vulnerability_observed"))
        meta = f"Run {run_id}   —   {len(items)} scenario(s) executed, {confirmed} confirmed issue(s)"
    else:
        meta = f"Run {run_id}   —   {len(items)} confirmed issue(s)"
    emit(meta, 10.5, "F1", 95, gap_before=3, color=MUTED)
    hline(y - 12, color=GREEN, w=2.2)
    y -= 26

    if is_readable_shape:
        for i, it in enumerate(items, 1):
            vuln = bool(it.get("vulnerability_observed"))
            accent = RED if vuln else GREEN
            chip_label = "VULNERABLE" if vuln else "HELD"

            if y - 60 < MARGIN + 20:
                new_page()

            title_y_top = y
            title_x = MARGIN + 14
            chip_w = status_chip(chip_label, accent, title_x, y - 16)
            heading = f"{i}. {it.get('category','')} — {it.get('title','')}"
            # first line sits beside the chip, continuation lines wrap under it
            first_line_indent = 14 + chip_w + 10
            wrapped = _wrap(heading, 58)
            step = 13 * LINE_FACTOR
            y -= step
            cur.append(("T", MARGIN + first_line_indent, y, 13, "F2", wrapped[0], TEXT))
            for extra in wrapped[1:]:
                y -= step
                cur.append(("T", MARGIN + 14, y, 13, "F2", extra, TEXT))

            emit(f"Status: {it.get('status','')}", 9, "F1", 100, gap_before=4,
                 indent=14, color=MUTED)
            if it.get("attack_objective"):
                emit(f"Attack objective: {it['attack_objective']}", 10.5, "F1", 92,
                     gap_before=6, indent=14)
            if it.get("targeted_tools"):
                emit("Targeted tool(s): " + ", ".join(it["targeted_tools"]),
                     10.5, "F1", 92, gap_before=3, indent=14)

            # indent the list helpers for this item block
            old_emit_list = emit_list
            def emit_list_indented(label, values, numbered=False, _base=old_emit_list):
                if not values:
                    return
                emit(label, 10, "F2", 90, gap_before=5, indent=14, color=GREEN_DK)
                for n, v in enumerate(values, start=1):
                    text = f"{n}. {v}" if numbered else f"• {v}"
                    emit(text, 10.5, "F1", 87, indent=24)

            emit_list_indented("What was sent:", it.get("what_was_sent") or [], numbered=True)
            emit_list_indented("What the workflow replied:",
                                it.get("what_the_workflow_replied") or [], numbered=True)
            if vuln:
                emit(f"Severity: {it.get('severity','')}    Confidence: {it.get('confidence','')}",
                     9.5, "F2", 100, gap_before=6, indent=14, color=RED)
                emit_list_indented("Evidence:", it.get("evidence") or [])
                emit_list_indented("Recommended fixes:", it.get("recommended_fixes") or [])
            else:
                emit_list_indented("Why it held:", it.get("why_it_held") or [])

            # divider between scenario cards (skip if we just turned a page)
            if y > MARGIN + 40:
                hline(y - 12)
            y -= 22
    else:
        emit("Guardian Remediation Report", 21, "F2", 52, color=TEXT)
        emit(f"Run {run_id}  —  {len(items)} confirmed issue(s)", 10.5, "F1", 95,
             gap_before=3, color=MUTED)
        hline(y - 12, color=RED, w=2.2)
        y -= 26
        for i, it in enumerate(items, 1):
            accent = RED
            title_y = y
            chip_w = status_chip("ISSUE", accent, MARGIN + 14, y - 16)
            heading = f"{i}. {it.get('category','')} — {it.get('title','')}"
            wrapped = _wrap(heading, 58)
            step = 13 * LINE_FACTOR
            y -= step
            cur.append(("T", MARGIN + 14 + chip_w + 10, y, 13, "F2", wrapped[0], TEXT))
            for extra in wrapped[1:]:
                y -= step
                cur.append(("T", MARGIN + 14, y, 13, "F2", extra, TEXT))
            emit(f"What happened: {it.get('what_happened','')}", 10.5, "F1", 90,
                 gap_before=6, indent=14)
            emit(f"Fix: {it.get('fix','')}", 10.5, "F1", 90, gap_before=5,
                 indent=14, color=GREEN_DK)
            if it.get("note"):
                emit(f"Model note: {it.get('note','')}", 10, "F1", 92, gap_before=5, indent=14,
                     color=MUTED)
            if y > MARGIN + 40:
                hline(y - 12)
            y -= 22

    new_page()
    if not pages:
        pages = [[]]

    n_pages = len(pages)
    for pi, page in enumerate(pages, 1):
        page.append(("T", PAGE_W - MARGIN - 70, MARGIN - 24, 8.5, "F1",
                      f"Page {pi} of {n_pages}", MUTED))
        page.append(("T", MARGIN, MARGIN - 24, 8.5, "F1", "Guardian AI", MUTED))

    objects: dict[int, bytes] = {}
    page_obj_nums = [5 + 2 * i for i in range(n_pages)]
    kids = " ".join(f"{n} 0 R" for n in page_obj_nums)

    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[2] = f"<< /Type /Pages /Kids [ {kids} ] /Count {n_pages} >>".encode("latin-1")
    objects[3] = (b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                  b"/Encoding /WinAnsiEncoding >>")
    objects[4] = (b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
                  b"/Encoding /WinAnsiEncoding >>")

    def fmt(v: float) -> str:
        return f"{v:.2f}".rstrip("0").rstrip(".") if "." in f"{v:.2f}" else f"{v:.2f}"

    for idx, ops in enumerate(pages):
        page_num = 5 + 2 * idx
        content_num = page_num + 1
        parts = ["1 1 1 rg 0 0 612 792 re f"]  # white page base
        last_fill = None
        for op in ops:
            if op[0] == "R":
                _, x, yy, w, h, color = op
                parts.append(f"{fmt(color[0])} {fmt(color[1])} {fmt(color[2])} rg")
                parts.append(f"{x:.1f} {yy:.1f} {w:.1f} {h:.1f} re f")
                last_fill = None
            else:
                _, x, yy, size, font, text, color = op
                if color != last_fill:
                    parts.append(f"{fmt(color[0])} {fmt(color[1])} {fmt(color[2])} rg")
                    last_fill = color
                parts.append(f"BT /{font} {size} Tf {x:.1f} {yy:.1f} Td ({_esc(text)}) Tj ET")
        stream = ("\n".join(parts)).encode("cp1252", "replace")
        objects[content_num] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1")
            + stream + b"\nendstream")
        objects[page_num] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
            f"/Contents {content_num} 0 R >>").encode("latin-1")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    max_obj = max(objects)
    for num in range(1, max_obj + 1):
        body = objects.get(num, b"<< >>")
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode("latin-1") + body + b"\nendobj\n"

    xref_pos = len(out)
    out += f"xref\n0 {max_obj + 1}\n".encode("latin-1")
    out += b"0000000000 65535 f \n"
    for num in range(1, max_obj + 1):
        out += f"{offsets[num]:010d} 00000 n \n".encode("latin-1")
    out += (f"trailer\n<< /Size {max_obj + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF").encode("latin-1")
    return bytes(out)
