from typing import Annotated, Sequence, TypedDict
from langchain_core.messages import BaseMessage
from langchain_core.messages import SystemMessage, AIMessage
from langchain_openai import AzureChatOpenAI
from langchain_core.tools import tool
from langgraph.graph.message import add_messages
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
import os
import hashlib
import requests
import math
from collections import Counter
from typing import Any

# ENV calls
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Agent definition
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]

##### Tools definition ######
@tool
def find_suspected_payload_events() -> dict:
    """Tool for calling database and retrieving suspected payload events."""
    ### Code for connecting to database and retrieving suspected payload events goes here ###
    return {"events": []}

@tool
def extract_payload_from_event(event_id: int) -> dict:
    """Tool for extracting payload from a suspected event."""
    ### Code for extracting payload from the event goes here ###

    # Logic
    # Locate PCAP via pcap_id ###
    # slice PCAP to [ts_start, ts_end]
    # export HTTP objects to folder (tshark)
    # return extracted file paths
    return {"payload": None}

@tool
def hash_and_vt_lookup(file_path: str) -> dict:
    """Tool for hashing a file and looking up its reputation on VirusTotal."""
    try:
        # Step 1: Hash the file using SHA256
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()

        # Step 2:Query VirusTotal API for reputation
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": VT_API_KEY
        }
        response = requests.get(url, headers=headers)

        # Step 3: Analyze response and return verdict
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {
                    "file_path": file_path,
                    "sha256": file_hash,
                    "vt_stats": stats,
                    "verdict": (
                        f"MALICIOUS: Flagged by {stats['malicious']} engines on VirusTotal."
                        if stats["malicious"] > 0 else
                        "CLEAN: No engines flagged this file on VirusTotal."
                    )
                }
        else:
            return {"error": f"VirusTotal API returned status code {response.status_code}"}

    except FileNotFoundError:
        return {"error": f"File not found: {file_path}"}
    except Exception as e:
        return {"error": str(e)}

# Hex headers for common executables
MAGIC_SIGNATURES = {
    "EXE/DLL (Windows PE)": b"\x4D\x5A",           # MZ header
    "ELF (Linux Executable)": b"\x7F\x45\x4C\x46", # ELF header
    "Mach-O (macOS 32-bit)": b"\xFE\xED\xFA\xCE",  # Mach-O 32-bit
    "Mach-O (macOS 64-bit)": b"\xFE\xED\xFA\xCF",  # Mach-O 64-bit
    "Mach-O (macOS FAT)": b"\xCA\xFE\xBA\xBE",     # Mach-O FAT binary
}

# Maps each detected file type to its legitimate extensions
EXPECTED_EXTENSIONS = {
    "EXE/DLL (Windows PE)": [".exe", ".dll", ".sys", ".scr"],
    "ELF (Linux Executable)": [".elf", ".so", ".axf", ".bin", ".o", ".out", ""],
    "Mach-O (macOS 32-bit)": [".dylib", ".o", ".bundle", ""],
    "Mach-O (macOS 64-bit)": [".dylib", ".o", ".bundle", ""],
    "Mach-O (macOS FAT)": [".dylib", ".o", ".bundle", ""],
}

@tool
def detect_file_magic(file_path: str) -> dict:
    """
    Tool for detecting if a payload is potentially malware using magic numbers.
    Flags any file whose header matches a known executable format (EXE, DLL, ELF, Mach-O)
    as potentially malicious, regardless of file extension.
    Also flags file type mismatches (e.g. a .txt file with an EXE header).
    """
    try:
        # Read first 8 bytes
        with open(file_path, "rb") as f:
            header_bytes = f.read(8)

        hex_header = header_bytes.hex().upper()
        detected_type = "Unknown"
        is_malware_candidate = False
        is_type_mismatch = False

        # Step 1: Identify true file type from hex header
        for file_type, magic in MAGIC_SIGNATURES.items():
            if header_bytes.startswith(magic):
                detected_type = file_type
                is_malware_candidate = True
                break

        # Step 2: Get the file's named extension
        file_extension = os.path.splitext(file_path)[1].lower()

        # Step 3: If we detected an executable type, check if the extension matches
        if is_malware_candidate:
            expected_exts = EXPECTED_EXTENSIONS[detected_type]
            if file_extension not in expected_exts:
                is_type_mismatch = True

        # Step 4: Verdict
        if is_type_mismatch:
            verdict = (
                f"HIGH RISK: File is named '{file_extension}' but hex header identifies it as "
                f"'{detected_type}'. Extension does not match — likely disguised executable."
            )
        elif is_malware_candidate:
            verdict = f"SUSPICIOUS: File is a '{detected_type}' executable."
        else:
            verdict = "NOT SUSPICIOUS: Hex header does not match any known executable format."

        return {
            "file_path": file_path,
            "file_extension": file_extension,
            "hex_header": hex_header,
            "detected_type": detected_type,
            "is_malware_candidate": is_malware_candidate,
            "is_type_mismatch": is_type_mismatch,
            "verdict": verdict
        }

    except FileNotFoundError:
        return {"error": f"File not found: {file_path}"}
    except Exception as e:
        return {"error": str(e)}

@tool
def compute_entropy_and_check_file_size(file_path: str) -> dict:
    """
    Tool for computing the Shannon entropy of a file.
    High entropy (>7.0) suggests the file may be packed, encrypted,
    or obfuscated — common traits of malware.
    Small files (<1KB) with high entropy are especially suspicious.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if len(data) == 0:
            return {"error": "File is empty."}

        file_size_bytes = len(data)

        # Calculate Shannon entropy
        byte_counts = Counter(data)
        entropy = 0.0

        for count in byte_counts.values():
            p_x = count / len(data)
            entropy -= p_x * math.log2(p_x)

        # Classify based on entropy score
        if entropy >= 7.0:
            risk = "HIGH ENTROPY"
            entropy_verdict = "Very high entropy detected — file may be compressed, encrypted, or obfuscated. Further analysis recommended."
        elif entropy >= 5.0:
            risk = "MODERATE ENTROPY"
            entropy_verdict = "Elevated entropy detected — file may be compressed or encoded. Not necessarily malicious."
        else:
            risk = "LOW ENTROPY"
            entropy_verdict = "Normal entropy levels detected. Likely plain text or structured data."

        # File size + high entropy check: small file + high entropy is especially suspicious
        small_file_flag = file_size_bytes < 1024 and entropy >= 7.0

        return {
            "file_path": file_path,
            "file_size_bytes": file_size_bytes,
            "entropy": round(entropy, 4),
            "verdict": f"{risk}: {entropy_verdict}",
            "small_high_entropy_warning": (
                "⚠️ CRITICAL: File is very small (<1KB) but has high entropy — suggests shellcode or encrypted dropper, warrants closer inspection."
                if small_file_flag else None
            )
        }

    except FileNotFoundError:
        return {"error": f"File not found: {file_path}"}
    except Exception as e:
        return {"error": str(e)}

##### Tools definition ######

# Tools list
tools = [find_suspected_payload_events, extract_payload_from_event, hash_and_vt_lookup, detect_file_magic, compute_entropy_and_check_file_size]


def _build_payload_graph():
    """Build the ReAct graph with Azure OpenAI."""
    llm = AzureChatOpenAI(
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        azure_deployment=os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
        api_version="2024-02-01",
        temperature=0,
    ).bind_tools(tools)

    tool_node = ToolNode(tools=tools)

    def model_call(state: AgentState) -> AgentState:
        system_prompt = SystemMessage(content=
            """You are a malware payload analysis AI assistant. Follow this strict workflow:

            STEP 1 - DATABASE RETRIEVAL (must do first):
                1. Call find_suspected_payload_events to get a list of suspected events.
                2. For each event returned, call extract_payload_from_event to extract the payload file path.

            STEP 2 - PAYLOAD ANALYSIS (run all tools on each extracted file path):
                3. Call detect_file_magic to check the file's hex header and detect type mismatches.
                4. Call compute_entropy_and_check_file_size to check if the file has suspicious entropy.
                5. Call hash_and_vt_lookup to check the file hash against VirusTotal.

            STEP 3 - FINAL REPORT:
                After all tools have been called, summarise all findings clearly.
                Include verdicts from each tool and state an overall risk assessment.
            """
        )
        response = llm.invoke([system_prompt] + list(state["messages"]))
        return {"messages": [response]}

    def should_continue(state: AgentState):
        messages = state["messages"]
        last_message = messages[-1]
        if not last_message.tool_calls:
            return "end"
        else:
            return "continue"

    graph = StateGraph(AgentState)
    graph.add_node("our_agent", model_call)
    graph.set_entry_point("our_agent")

    graph.add_node("tools", tool_node)

    graph.add_conditional_edges(
        "our_agent",
        should_continue,
        {
            "continue": "tools",
            "end": END,
        },
    )

    graph.add_edge("tools", "our_agent")
    return graph.compile()


def payload_agent_node(state: dict) -> dict:
    messages = list(state.get("messages", []))
    app = _build_payload_graph()
    result = app.invoke({"messages": messages})
    payload_messages = list(result.get("messages", []))
    last_content = ""
    if payload_messages:
        last_message = payload_messages[-1]
        last_content = getattr(last_message, "content", "") or str(last_message)

    updated_messages = messages + payload_messages[len(messages):]
    return {
        **state,
        "payload_findings": {
            "summary": last_content or "Payload analysis completed.",
            "raw_messages": payload_messages,
        },
        "messages": updated_messages,
    }


# For viewing of states and if tool is used
def print_stream(stream):
    for s in stream:
        message = s["messages"][-1]
        if isinstance(message, tuple):
            print(message)
        else:
            message.pretty_print()
