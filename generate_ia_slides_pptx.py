"""
Generate Initial Access Agent slides as .pptx, matching SC4063 Group 12 style.
"""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt
import copy

OUTPUT = "/Users/argel/Desktop/NTU/Y4S2/SC4063/llm_pcap_analyst/initial_access_slides.pptx"

# ── Slide size: 16:9 widescreen (13.33 x 7.5 inches) ─────────────────────────
W = Inches(13.33)
H = Inches(7.5)

# ── Colours ───────────────────────────────────────────────────────────────────
BLACK      = RGBColor(0x00, 0x00, 0x00)
WHITE      = RGBColor(0xFF, 0xFF, 0xFF)
DARK_BG    = RGBColor(0x1E, 0x1E, 0x2E)
CODE_FG    = RGBColor(0xCD, 0xD6, 0xF4)
PURPLE     = RGBColor(0x7C, 0x6F, 0xCD)
GRAY_BORD  = RGBColor(0xCC, 0xCC, 0xCC)
BOLD_BLK   = RGBColor(0x11, 0x11, 0x11)
DIM_GRAY   = RGBColor(0x55, 0x55, 0x55)
KW_BLUE    = RGBColor(0x89, 0xB4, 0xFA)
KW_GREEN   = RGBColor(0xA6, 0xE3, 0xA1)
KW_YELLOW  = RGBColor(0xF9, 0xE2, 0xAF)


def new_prs():
    prs = Presentation()
    prs.slide_width  = W
    prs.slide_height = H
    return prs


def blank_slide(prs):
    blank_layout = prs.slide_layouts[6]   # completely blank
    return prs.slides.add_slide(blank_layout)


def add_bg(slide, color=WHITE):
    from pptx.util import Pt
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = color


def add_textbox(slide, text, x, y, w, h,
                font_name="Calibri", font_size=18,
                bold=False, color=BLACK, align=PP_ALIGN.LEFT,
                word_wrap=True):
    txBox = slide.shapes.add_textbox(x, y, w, h)
    tf = txBox.text_frame
    tf.word_wrap = word_wrap
    p = tf.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.name = font_name
    run.font.size = Pt(font_size)
    run.font.bold = bold
    run.font.color.rgb = color
    return txBox


def add_rounded_border(slide):
    """Add a rounded rectangle border like the existing slides."""
    from pptx.util import Inches, Pt
    from pptx.enum.shapes import MSO_SHAPE_TYPE
    margin = Inches(0.35)
    shape = slide.shapes.add_shape(
        1,  # MSO_SHAPE_TYPE.ROUNDED_RECTANGLE = 5, but add_shape uses auto_shape_type
        margin, margin,
        W - 2 * margin, H - 2 * margin
    )
    shape.fill.background()       # transparent fill
    shape.line.color.rgb = GRAY_BORD
    shape.line.width = Pt(1.2)
    return shape


def add_code_block(slide, lines, x, y, w, h, title=None):
    """Dark code block with monospace text."""
    from pptx.util import Pt
    from pptx.dml.color import RGBColor

    # Dark background rectangle
    bg = slide.shapes.add_shape(1, x, y, w, h)
    bg.fill.solid()
    bg.fill.fore_color.rgb = DARK_BG
    bg.line.fill.background()

    # Optional title bar
    title_h = Inches(0.28)
    if title:
        title_bar = slide.shapes.add_shape(1, x, y, w, title_h)
        title_bar.fill.solid()
        title_bar.fill.fore_color.rgb = RGBColor(0x31, 0x32, 0x44)
        title_bar.line.fill.background()
        add_textbox(slide, title,
                    x + Inches(0.1), y + Inches(0.03),
                    w - Inches(0.2), title_h,
                    font_name="Consolas", font_size=9,
                    bold=True, color=RGBColor(0xCB, 0xA6, 0xF7))

    # Code text box
    code_y = y + (title_h if title else Inches(0.08))
    code_h = h - (title_h if title else Inches(0.08))
    txBox = slide.shapes.add_textbox(
        x + Inches(0.12), code_y + Inches(0.05),
        w - Inches(0.24), code_h - Inches(0.1)
    )
    tf = txBox.text_frame
    tf.word_wrap = False

    for i, line in enumerate(lines):
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.space_before = Pt(0)
        p.space_after  = Pt(0)

        # Colour comments differently
        stripped = line.lstrip()
        if stripped.startswith("#"):
            run = p.add_run()
            run.text = line
            run.font.name = "Consolas"
            run.font.size = Pt(9)
            run.font.color.rgb = RGBColor(0x6C, 0x70, 0x86)
        else:
            run = p.add_run()
            run.text = line
            run.font.name = "Consolas"
            run.font.size = Pt(9)
            run.font.color.rgb = CODE_FG


def build_content_slide(prs, title, bullets, code_lines=None, code_title=None):
    """
    Content slide with:
    - Rounded border
    - Title centered at top
    - Bullet list on left
    - Optional code block on right
    """
    slide = blank_slide(prs)
    add_bg(slide)
    add_rounded_border(slide)

    margin = Inches(0.5)

    # Title
    add_textbox(slide, title,
                margin, Inches(0.35),
                W - 2 * margin, Inches(0.7),
                font_name="Garamond", font_size=28,
                bold=False, color=BLACK, align=PP_ALIGN.CENTER)

    # Column widths
    if code_lines:
        left_w  = Inches(5.4)
        right_x = Inches(5.9)
        right_w = W - right_x - margin
    else:
        left_w  = W - 2 * margin
        right_x = None
        right_w = None

    # Bullet list text box
    bul_x = margin + Inches(0.1)
    bul_y = Inches(1.2)
    bul_h = H - bul_y - margin
    txBox = slide.shapes.add_textbox(bul_x, bul_y, left_w - Inches(0.2), bul_h)
    tf = txBox.text_frame
    tf.word_wrap = True

    for i, item in enumerate(bullets):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_before = Pt(2)
        p.space_after  = Pt(2)

        if item is None:
            # spacer
            p.space_before = Pt(8)
            run = p.add_run()
            run.text = ""
            run.font.size = Pt(6)
            continue

        if item.startswith("##"):
            # Sub-heading
            run = p.add_run()
            run.text = item[2:].strip()
            run.font.name  = "Calibri"
            run.font.size  = Pt(14)
            run.font.bold  = True
            run.font.color.rgb = BOLD_BLK
            p.level = 0
            continue

        if item.startswith("  "):
            # Sub-bullet
            p.level = 1
            run = p.add_run()
            run.text = item.strip()
            run.font.name  = "Calibri"
            run.font.size  = Pt(12.5)
            run.font.bold  = False
            run.font.color.rgb = DIM_GRAY
            continue

        # Normal bullet
        p.level = 0
        run = p.add_run()
        run.text = item
        run.font.name  = "Calibri"
        run.font.size  = Pt(14)
        run.font.bold  = False
        run.font.color.rgb = BLACK

    # Code block
    if code_lines and right_x:
        code_y = Inches(1.1)
        code_h = H - code_y - margin
        add_code_block(slide, code_lines,
                       right_x, code_y, right_w, code_h,
                       title=code_title)


def build_section_slide(prs, title):
    """Section divider slide: large centred text, purple blob hint via shape."""
    slide = blank_slide(prs)
    add_bg(slide)

    # Purple blob (circle with soft colour)
    blob = slide.shapes.add_shape(1,
        Inches(-0.3), Inches(0.8),
        Inches(4.5), Inches(4.5))
    blob.fill.solid()
    blob.fill.fore_color.rgb = RGBColor(0xD0, 0xCC, 0xF0)
    blob.line.fill.background()
    blob.shadow.inherit = False

    # Title text
    add_textbox(slide, title,
                Inches(1), Inches(2.8),
                Inches(11.33), Inches(2),
                font_name="Garamond", font_size=64,
                bold=False, color=BLACK, align=PP_ALIGN.CENTER)


# ── Slide content ─────────────────────────────────────────────────────────────

def main():
    prs = new_prs()

    # 1. Section header
    build_section_slide(prs, "INITIAL ACCESS AGENT")

    # 2. Two-Pass Design
    build_content_slide(
        prs,
        title="TWO-PASS DESIGN",
        bullets=[
            "##Pass 1 — Zeek Fast Scan (no PCAP needed)",
            "  Parses zeek.rdp log for brute-force count & session bytes",
            "  Populates InitialAccessFindings used by needs_pcap_drilldown()",
            "  Runs across all 9 days — cheap and fast",
            None,
            "##Pass 2 — LLM ReAct Loop (tshark)",
            "  Triggered only on days flagged by Pass 1",
            "  ForensicAgent drives up to MAX_AGENT_STEPS = 30 tshark calls",
            "  Uses Azure OpenAI function-calling (not LangGraph tools)",
            "  Produces full Markdown forensic report",
            None,
            "Rationale: Pass 1 filters 9 days to 1–2 suspect days;",
            "Pass 2 only runs where evidence exists — minimises cost",
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
            "        if dur > 30:  # successful session",
            "            successful_bytes += rec.get('bytes', 0)",
            "        else:",
            "            brute_force_count += 1",
            "    return {",
            "        'brute_force_count': brute_force_count,",
            "        'successful_session_bytes': successful_bytes,",
            "    }",
            "",
            "# Pass 2: LLM ReAct loop (only on flagged days)",
            "def run(self) -> str:",
            "    self._run_seed_queries()",
            "    for step in range(MAX_AGENT_STEPS):",
            "        response = self._call_llm()",
            "        if response.tool_calls:",
            "            self._dispatch_tool(response.tool_calls[0])",
            "        else:",
            "            break  # submit_report called",
        ],
        code_title="initial_access_agent.py",
    )

    # 3. System Prompt — Reasoning Principles
    build_content_slide(
        prs,
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
            "  Means the network was breached before this capture window",
        ],
        code_lines=[
            "SYSTEM_PROMPT = \"\"\"",
            "You are an expert network forensic analyst",
            "specialising in initial access vector identification.",
            "",
            "CRITICAL ANALYSIS PRINCIPLES",
            "",
            "* The IPs performing brute-force are NOT necessarily",
            "  the ones that succeeded. The actual attacker may",
            "  be a DIFFERENT IP using stolen credentials.",
            "",
            "* A successful session is DRAMATICALLY larger than",
            "  a failed login attempt:",
            "  Failed RDP  = 2-5 KB, ~20 frames, <10 s",
            "  Success RDP = 50-500+ KB, hundreds of frames,",
            "                minutes of duration.",
            "",
            "* Examine TCP conversations sorted by total bytes —",
            "  the successful login is a visible outlier.",
            "",
            "* Always check if C2 infrastructure was already",
            "  active at capture start — if so, the network was",
            "  compromised BEFORE this capture period.",
            "\"\"\"",
        ],
        code_title="SYSTEM_PROMPT (initial_access_agent.py)",
    )

    # 4. Seed Queries
    build_content_slide(
        prs,
        title="SEED QUERIES",
        bullets=[
            "Auto-executed before the ReAct loop starts",
            "Ensures the LLM cannot miss critical upfront evidence",
            None,
            "##1. PCAP Overview",
            "  pcap_overview — capture metadata: time range, packet count, size",
            None,
            "##2. RDP Brute-Force Sources",
            "  group_count: SYNs to port 3389 grouped by source IP",
            "  Identifies all brute-force participants (top 25)",
            None,
            "##3. TCP Conversations on Port 3389",
            "  tcp_conversations sorted by bytes (top 50)",
            "  Successful session is the visible byte-count outlier",
            None,
            "##4. C2 / RMM Tool DNS at Capture Start",
            "  packet_query: dns.qry.name contains rmm / tactical / mesh",
            "  Detects pre-existing C2 beacons from first packets",
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
            "        'tcp.dstport==3389 &&",
            "         tcp.flags.syn==1 &&",
            "         tcp.flags.ack==0',",
            "      'group_by_field': 'ip.src',",
            "      'top_n': 25,",
            "    },",
            "  },",
            "  {",
            "    'label': 'TCP Conversations port 3389',",
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
            "      'fields': ['frame.time','ip.src',",
            "                 'dns.qry.name'],",
            "      'max_packets': 50,",
            "    },",
            "  },",
            "]",
        ],
        code_title="SEED_QUERIES (initial_access_agent.py)",
    )

    # 5. Output Schema
    build_content_slide(
        prs,
        title="OUTPUT SCHEMA — InitialAccessFindings",
        bullets=[
            "Structured dataclass written into PipelineState",
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
            "  iocs — List[IOC] with type, value & confidence",
            None,
            "Fields also feed needs_pcap_drilldown() thresholds:",
            "  successful_session_bytes > 10,000 → flag for PCAP drill-down",
            "  brute_force_count > 1,000 → flag for PCAP drill-down",
        ],
        code_lines=[
            "@dataclass",
            "class InitialAccessFindings:",
            "    summary: str = ''",
            "    patient_zero:    Optional[str] = None",
            "    attack_vector:   Optional[str] = None",
            "    attacker_ip:     Optional[str] = None",
            "    attacker_port:   Optional[int] = None",
            "    exposed_service: Optional[str] = None",
            "    brute_force_count:        Optional[int] = None",
            "    successful_session_bytes: Optional[int] = None",
            "    session_start: Optional[str] = None",
            "    session_end:   Optional[str] = None",
            "    pre_existing_compromise: bool = False",
            "    iocs: List[IOC] = field(default_factory=list)",
            "    report_markdown: str = ''",
            "    raw: dict[str, Any] = field(default_factory=dict)",
            "",
            "@dataclass",
            "class IOC:",
            "    ioc_type:     str  # ip|domain|hash|port|file",
            "    value:        str",
            "    source_agent: str",
            "    confidence:   str  # high|medium|low",
            "    notes:        str = ''",
        ],
        code_title="shared/data_contract.py",
    )

    # 6. Adapter — Markdown → Structured Data
    build_content_slide(
        prs,
        title="ADAPTER — MARKDOWN TO STRUCTURED DATA",
        bullets=[
            "ForensicAgent outputs free-form Markdown — not JSON",
            "initial_access_adapter.py bridges this to PipelineState",
            None,
            "##_parse_report() extracts fields via regex:",
            "  Patient Zero — matches 'Patient Zero: <IP>'",
            "  Attacker IP — 'successful login from <IP>'",
            "  Exposed port — 'port <number>'",
            "  Brute-force count — '<N> SYN / failed'",
            "  Session bytes — first '<N> bytes' mention",
            "  Pre-existing C2 — keywords: 'c2 beacon', 'return visit'",
            "  IOCs — all IPs found in the IOC section",
            None,
            "Why regex instead of structured output?",
            "  ForensicAgent uses raw Azure OpenAI SDK (not LangChain)",
            "  submit_report accepts free Markdown — simpler prompt",
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
            "      r'attacker ip[^\\n]*?[:\\-]\\s*([0-9.]+)',",
            "      r'successful (?:login|session) from\\s+([0-9.]+)',",
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

    prs.save(OUTPUT)
    print(f"Saved → {OUTPUT}")


if __name__ == "__main__":
    main()
