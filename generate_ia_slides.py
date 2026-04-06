"""
Generate Initial Access Agent slides as PDF, matching the SC4063 Group 12 slide style.
"""
from reportlab.lib.pagesizes import landscape
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor, Color
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import math, os

# ── Slide dimensions (16:9 at 96dpi equivalent) ──────────────────────────────
W, H = 1280, 720
PAGE = (W, H)

# ── Colours ───────────────────────────────────────────────────────────────────
WHITE       = HexColor("#FFFFFF")
BLACK       = HexColor("#000000")
DARK_BG     = HexColor("#1E1E2E")   # code block background
CODE_FG     = HexColor("#CDD6F4")   # code text
PURPLE_BLOB = HexColor("#7C6FCD")   # blob colour (semi-transparent drawn as gradient)
BORDER_GRAY = HexColor("#CCCCCC")
BULLET_GRAY = HexColor("#333333")
BOLD_BLACK  = HexColor("#111111")
DIM_GRAY    = HexColor("#555555")
KEYWORD_BLUE= HexColor("#89B4FA")
KEYWORD_GRN = HexColor("#A6E3A1")
KEYWORD_YLW = HexColor("#F9E2AF")
KEYWORD_RED = HexColor("#F38BA8")

OUTPUT = "/Users/argel/Desktop/NTU/Y4S2/SC4063/llm_pcap_analyst/initial_access_slides.pdf"


# ── Helpers ───────────────────────────────────────────────────────────────────

def draw_blob(c, cx, cy, r=200, alpha=0.18):
    """Draw a soft radial purple blob."""
    steps = 30
    for i in range(steps, 0, -1):
        frac = i / steps
        a = alpha * (1 - frac) ** 0.5
        col = Color(
            PURPLE_BLOB.red,
            PURPLE_BLOB.green,
            PURPLE_BLOB.blue,
            alpha=a,
        )
        c.setFillColor(col)
        c.circle(cx, cy, r * frac, fill=1, stroke=0)


def draw_rounded_border(c, margin=40):
    """Draw the rounded-rectangle border seen on content slides."""
    c.setStrokeColor(BORDER_GRAY)
    c.setLineWidth(1.5)
    c.roundRect(margin, margin, W - 2 * margin, H - 2 * margin, 18, fill=0, stroke=1)


def section_slide(c, title):
    """Render a section-divider slide (large centred title + blob)."""
    c.setFillColor(WHITE)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    draw_blob(c, cx=200, cy=H - 260, r=230)
    c.setFillColor(BLACK)
    c.setFont("Helvetica", 64)
    c.drawCentredString(W / 2, H / 2 - 10, title)
    c.showPage()


def content_slide(c, title, bullets, code_lines=None,
                  code_title=None, two_col=True):
    """
    Render a content slide with:
    - rounded border
    - title at top
    - bullet list on left (or full-width if no code)
    - optional dark-bg code block on right
    """
    c.setFillColor(WHITE)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    draw_rounded_border(c)

    # Title
    c.setFillColor(BLACK)
    c.setFont("Helvetica-Bold", 32)
    c.drawCentredString(W / 2, H - 90, title)

    # Layout columns
    margin = 60
    if two_col and code_lines:
        left_w  = W * 0.42
        right_x = W * 0.45
        right_w = W - right_x - margin
    else:
        left_w  = W - 2 * margin
        right_x = None
        right_w = None

    # Bullets
    x = margin + 10
    y = H - 145
    line_h = 36

    for item in bullets:
        if item is None:               # spacer
            y -= line_h * 0.5
            continue
        if item.startswith("##"):      # sub-heading
            text = item[2:].strip()
            c.setFillColor(BOLD_BLACK)
            c.setFont("Helvetica-Bold", 16)
            c.drawString(x, y, text)
            y -= line_h * 0.8
            continue
        if item.startswith("  "):      # sub-bullet
            bx = x + 24
            text = item.strip()
            c.setFillColor(DIM_GRAY)
            c.setFont("Helvetica", 13)
            c.drawString(bx - 10, y + 4, "–")
            _draw_wrapped(c, text, bx + 4, y, left_w - bx - 10, 13, line_h * 0.75)
            y -= line_h * 0.82
            continue
        # Normal bullet
        c.setFillColor(BLACK)
        c.circle(x - 4, y + 6, 3, fill=1, stroke=0)
        c.setFillColor(BULLET_GRAY)
        c.setFont("Helvetica", 15)
        lines_used = _draw_wrapped(c, item, x + 10, y, left_w - x - 20, 15, line_h * 0.85)
        y -= line_h * 0.9 * max(1, lines_used)

    # Code block
    if code_lines and right_x:
        code_x = right_x
        code_y = H - 130
        code_h = H - code_y - margin + 40
        _draw_code_block(c, code_lines, code_x, code_y - code_h,
                         right_w, code_h, code_title)

    c.showPage()


def _draw_wrapped(c, text, x, y, max_w, font_size, line_h):
    """Draw text wrapped to max_w. Returns number of lines used."""
    words = text.split()
    lines, cur = [], []
    for w in words:
        trial = " ".join(cur + [w])
        if c.stringWidth(trial, "Helvetica", font_size) <= max_w:
            cur.append(w)
        else:
            if cur:
                lines.append(" ".join(cur))
            cur = [w]
    if cur:
        lines.append(" ".join(cur))
    for i, ln in enumerate(lines):
        c.drawString(x, y - i * line_h, ln)
    return len(lines)


def _draw_code_block(c, lines, x, y, w, h, title=None):
    """Draw a dark-background code block."""
    pad = 10
    # Background
    c.setFillColor(DARK_BG)
    c.roundRect(x, y, w, h, 8, fill=1, stroke=0)

    if title:
        c.setFillColor(HexColor("#313244"))
        c.roundRect(x, y + h - 26, w, 26, 8, fill=1, stroke=0)
        c.setFillColor(HexColor("#CBA6F7"))
        c.setFont("Helvetica-Bold", 11)
        c.drawString(x + pad, y + h - 16, title)

    c.setFillColor(CODE_FG)
    c.setFont("Courier", 10.5)
    ty = y + h - (36 if title else 22)
    for ln in lines:
        if ty < y + pad:
            break
        _draw_coloured_code_line(c, ln, x + pad, ty, w - 2 * pad)
        ty -= 15


def _draw_coloured_code_line(c, line, x, y, max_w):
    """Very simple syntax colouring: keywords, strings, comments."""
    import re
    # If it's a comment
    stripped = line.lstrip()
    if stripped.startswith("#"):
        c.setFillColor(HexColor("#6C7086"))
        c.setFont("Courier", 10.5)
        c.drawString(x, y, line[:int(max_w / 6.3)])
        return

    # Tokenise roughly
    keywords = {"def", "class", "return", "if", "else", "for", "in",
                 "import", "from", "None", "True", "False", "and", "or",
                 "not", "self", "Optional", "List", "bool", "str", "int",
                 "dict", "Any", "field"}
    decorators = {"@dataclass", "@tool"}

    cur_x = x
    # Split on spaces to colour-code keywords (simple approach)
    tokens = re.split(r'(\s+)', line)
    for tok in tokens:
        stripped_tok = tok.strip()
        if not tok:
            continue
        if stripped_tok in keywords:
            col = KEYWORD_BLUE
            font = "Courier-Bold"
        elif stripped_tok in decorators or stripped_tok.startswith("@"):
            col = KEYWORD_GRN
            font = "Courier"
        elif stripped_tok.startswith('"') or stripped_tok.startswith("'"):
            col = KEYWORD_YLW
            font = "Courier"
        elif stripped_tok.endswith(":") and stripped_tok[:-1] in keywords:
            col = KEYWORD_BLUE
            font = "Courier-Bold"
        else:
            col = CODE_FG
            font = "Courier"
        c.setFillColor(col)
        c.setFont(font, 10.5)
        w_tok = c.stringWidth(tok, font, 10.5)
        if cur_x + w_tok > x + max_w:
            break
        c.drawString(cur_x, y, tok)
        cur_x += w_tok


# ── Build slides ──────────────────────────────────────────────────────────────

def make_slides():
    c = canvas.Canvas(OUTPUT, pagesize=PAGE)
    c.setTitle("SC4063 Group 12 – Initial Access Agent Slides")

    # ── Slide 1: Section header ───────────────────────────────────────────────
    section_slide(c, "INITIAL ACCESS AGENT")

    # ── Slide 2: Two-Pass Design ──────────────────────────────────────────────
    content_slide(
        c,
        title="TWO-PASS DESIGN",
        bullets=[
            "##Pass 1 — Zeek Fast Scan (no PCAP)",
            "  Parses zeek.rdp log for brute-force count & session bytes",
            "  Populates InitialAccessFindings used by needs_pcap_drilldown()",
            "  Runs for all 9 days — cheap and fast",
            None,
            "##Pass 2 — LLM ReAct Loop (tshark)",
            "  Triggered only on days flagged by Pass 1",
            "  ForensicAgent drives up to MAX_AGENT_STEPS = 30 tshark calls",
            "  Uses Azure OpenAI function-calling (not LangGraph tools)",
            "  Produces full Markdown forensic report",
            None,
            "Rationale: Pass 1 filters 9 days to 1–2; Pass 2 only runs",
            "where evidence exists — minimises LLM cost & runtime",
        ],
        code_lines=[
            "# initial_access_agent.py",
            "MAX_AGENT_STEPS = 30",
            "MAX_OUTPUT_CHARS = 15_000",
            "",
            "# Pass 1: deterministic Zeek scan",
            "def _zeek_rdp_scan(zeek_files) -> dict:",
            "    rdp_log = zeek_files.get('zeek.rdp.ndjson')",
            "    brute_force_count = 0",
            "    successful_bytes  = 0",
            "    for rec in _iter_ndjson(rdp_log):",
            "        dur = rec.get('duration', 0)",
            "        if dur > 30:   # successful session",
            "            successful_bytes += rec.get('bytes', 0)",
            "        else:",
            "            brute_force_count += 1",
            "    return {",
            "        'brute_force_count':      brute_force_count,",
            "        'successful_session_bytes': successful_bytes,",
            "    }",
            "",
            "# Pass 2: LLM ReAct loop (only if flagged)",
            "def run(self) -> str:",
            "    self._run_seed_queries()",
            "    for step in range(MAX_AGENT_STEPS):",
            "        response = self._call_llm()",
            "        if response.tool_calls:",
            "            self._dispatch_tool(response.tool_calls[0])",
            "        else:",
            "            break   # report submitted",
        ],
        code_title="initial_access_agent.py",
    )

    # ── Slide 3: System Prompt — Reasoning Principles ─────────────────────────
    content_slide(
        c,
        title="SYSTEM PROMPT — REASONING PRINCIPLES",
        bullets=[
            "Brute-force source IPs are NOT the successful attacker",
            "  The actual login may come from a different IP using stolen creds",
            None,
            "Session size is the key discriminator",
            "  Failed RDP = 2–5 KB, ~20 frames, < 10 seconds",
            "  Successful RDP = 50–500+ KB, hundreds of frames, minutes",
            None,
            "Sort TCP conversations by bytes — the successful",
            "session is a visible outlier among hundreds of failures",
            None,
            "Check for pre-existing compromise",
            "  C2 beacons / RMM tool DNS queries active from capture start",
            "  Means network was already breached before the capture window",
        ],
        code_lines=[
            "SYSTEM_PROMPT = \"\"\"",
            "You are an expert network forensic analyst",
            "specialising in initial access vector identification.",
            "",
            "CRITICAL ANALYSIS PRINCIPLES",
            "",
            "* The IPs performing brute-force are NOT necessarily",
            "  the ones that succeeded. The actual attacker may be",
            "  a DIFFERENT IP using stolen credentials.",
            "",
            "* A successful interactive session is DRAMATICALLY",
            "  larger than a failed login attempt.",
            "  Failed RDP  = 2-5 KB, ~20 frames, <10 s",
            "  Success RDP = 50-500+ KB, hundreds of frames,",
            "                minutes of duration.",
            "",
            "* You MUST examine TCP conversations on the targeted",
            "  port sorted by total bytes to find the outlier.",
            "",
            "* Always check whether C2 infrastructure was already",
            "  active at the very start of the capture — if so,",
            "  the network was compromised BEFORE this capture.",
            "\"\"\"",
        ],
        code_title="SYSTEM_PROMPT (initial_access_agent.py)",
    )

    # ── Slide 4: Seed Queries ─────────────────────────────────────────────────
    content_slide(
        c,
        title="SEED QUERIES",
        bullets=[
            "Auto-executed before the ReAct loop starts",
            "Prevents the LLM from missing critical upfront evidence",
            None,
            "##1. PCAP Overview",
            "  Capture metadata: time range, packet count, file size",
            None,
            "##2. RDP Brute-Force Sources",
            "  group_count: SYNs to port 3389, grouped by source IP",
            "  Identifies all brute-force participants",
            None,
            "##3. TCP Conversations on Port 3389",
            "  tcp_conversations sorted by bytes (top 50)",
            "  The successful session is the visible outlier",
            None,
            "##4. C2 / RMM Tool DNS Queries",
            "  packet_query: dns.qry.name contains rmm/tactical/mesh",
            "  Detects pre-existing C2 beacons from capture start",
        ],
        code_lines=[
            "SEED_QUERIES = [",
            "  {",
            "    'label': 'PCAP Overview',",
            "    'tool':  'pcap_overview',",
            "    'args':  {},",
            "  },",
            "  {",
            "    'label': 'RDP Brute-Force Sources',",
            "    'tool':  'group_count',",
            "    'args':  {",
            "      'display_filter':",
            "        'tcp.dstport==3389 && tcp.flags.syn==1'",
            "        ' && tcp.flags.ack==0',",
            "      'group_by_field': 'ip.src',",
            "      'top_n': 25,",
            "    },",
            "  },",
            "  {",
            "    'label': 'TCP Conversations port 3389 by bytes',",
            "    'tool':  'tcp_conversations',",
            "    'args':  {",
            "      'display_filter': 'tcp.port == 3389',",
            "      'top_n': 50,",
            "    },",
            "  },",
            "  {",
            "    'label': 'C2/RMM DNS at capture start',",
            "    'tool':  'packet_query',",
            "    'args':  {",
            "      'display_filter':",
            "        'dns.qry.name contains \"rmm\" or",
            "         dns.qry.name contains \"tactical\"',",
            "      'max_packets': 50,",
            "    },",
            "  },",
            "]",
        ],
        code_title="SEED_QUERIES (initial_access_agent.py)",
    )

    # ── Slide 5: Output Schema — InitialAccessFindings ───────────────────────
    content_slide(
        c,
        title="OUTPUT SCHEMA — InitialAccessFindings",
        bullets=[
            "Structured dataclass written to PipelineState",
            "Consumed by Lateral Movement, Payload agents & report writer",
            None,
            "##Key fields:",
            "  patient_zero — first compromised host IP",
            "  attack_vector — e.g. 'RDP brute-force'",
            "  attacker_ip — IP that made the successful login",
            "  exposed_service — e.g. 'RDP/3389'",
            "  brute_force_count — number of failed attempts",
            "  successful_session_bytes — size of the winning session",
            "  session_start / session_end — ISO-8601 timestamps",
            "  pre_existing_compromise — bool (C2 already active?)",
            "  iocs — List[IOC] with confidence levels",
            None,
            "Fields also feed needs_pcap_drilldown() thresholds:",
            "  successful_session_bytes > 10,000 → flag for PCAP drill-down",
            "  brute_force_count > 1,000 → flag for PCAP drill-down",
        ],
        code_lines=[
            "@dataclass",
            "class InitialAccessFindings:",
            "    \"\"\"Output schema for the Initial Access agent.\"\"\"",
            "    summary: str = ''",
            "    patient_zero:    Optional[str] = None",
            "    attack_vector:   Optional[str] = None",
            "    attacker_ip:     Optional[str] = None",
            "    attacker_port:   Optional[int] = None",
            "    exposed_service: Optional[str] = None",
            "    brute_force_count:         Optional[int] = None",
            "    successful_session_bytes:  Optional[int] = None",
            "    session_start: Optional[str] = None  # ISO-8601",
            "    session_end:   Optional[str] = None",
            "    pre_existing_compromise: bool = False",
            "    iocs: List[IOC] = field(default_factory=list)",
            "    report_markdown: str = ''",
            "    raw: dict[str, Any] = field(default_factory=dict)",
            "",
            "@dataclass",
            "class IOC:",
            "    ioc_type:   str   # ip | domain | hash | port | file",
            "    value:      str",
            "    source_agent: str",
            "    confidence: str   # high | medium | low",
            "    notes:      str = ''",
        ],
        code_title="shared/data_contract.py",
    )

    # ── Slide 6: Adapter — Markdown → Structured Data ────────────────────────
    content_slide(
        c,
        title="ADAPTER — MARKDOWN TO STRUCTURED DATA",
        bullets=[
            "ForensicAgent outputs free-form Markdown — not JSON",
            "initial_access_adapter.py bridges this to PipelineState",
            None,
            "##_parse_report() extracts via regex:",
            "  Patient Zero — looks for 'Patient Zero: <IP>'",
            "  Attacker IP — 'successful login from <IP>'",
            "  Exposed port — 'port <number>'",
            "  Brute-force count — '<N> SYN / failed'",
            "  Session bytes — first '<N> bytes' mention",
            "  Pre-existing C2 — keyword: 'pre-existing', 'c2 beacon'",
            "  IOCs — all IPs in the IOC section of the report",
            None,
            "Why regex not structured output?",
            "  ForensicAgent uses raw Azure OpenAI SDK (not LangChain)",
            "  submit_report tool accepts free Markdown — simpler prompt",
            "  Regex post-processing is more robust than forcing JSON mid-loop",
        ],
        code_lines=[
            "# agents/initial_access_adapter.py",
            "",
            "def _parse_report(report: str) -> InitialAccessFindings:",
            "    findings = InitialAccessFindings(",
            "        report_markdown=report,",
            "        raw={'full_report': report},",
            "    )",
            "",
            "    # Patient Zero",
            "    pz = re.search(",
            "        r'patient zero[^\\n]*?[:\\-]\\s*([0-9.]+)',",
            "        report, re.I)",
            "    if pz:",
            "        findings.patient_zero = pz.group(1).strip()",
            "",
            "    # Attacker IP",
            "    for pat in [",
            "        r'attacker ip[^\\n]*?[:\\-]\\s*([0-9.]+)',",
            "        r'successful (?:login|session) from\\s+([0-9.]+)',",
            "    ]:",
            "        m = re.search(pat, report, re.I)",
            "        if m:",
            "            findings.attacker_ip = m.group(1).strip()",
            "            break",
            "",
            "    # Pre-existing compromise",
            "    if re.search(",
            "        r'pre.existing|c2 beacon|return visit',",
            "        report, re.I):",
            "        findings.pre_existing_compromise = True",
            "",
            "    return findings",
        ],
        code_title="agents/initial_access_adapter.py",
    )

    c.save()
    print(f"Saved → {OUTPUT}")


if __name__ == "__main__":
    make_slides()
