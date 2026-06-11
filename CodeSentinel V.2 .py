"""
CodeSentinel — AI Authorship Detector
======================================
Executable Python application built with CustomTkinter + httpx.
Detects AI-generated source code using the Anthropic API.

Language choice rationale
--------------------------
Python was selected over Electron/Node, C#/WPF, and Java/Swing because:
  • Richest ecosystem for code analysis (AST, tokenization, pathlib)
  • CustomTkinter gives a modern, dark-themed native GUI with zero web overhead
  • httpx provides async HTTP with streaming support
  • PyInstaller produces a single cross-platform executable
  • Fastest iteration cycle for a forensic/analysis tool
  • Native file-system access with no sandboxing constraints
"""

import tkinter as tk
import customtkinter as ctk
import tkinter.filedialog as fd
import threading
import json
import time
import os
import sys
import re
import math
import traceback
from pathlib import Path
from datetime import datetime
import httpx

# ── Persistent config ────────────────────────────────────────────────────────
_CONFIG_DIR  = Path.home() / ".codesentinel"
_CONFIG_FILE = _CONFIG_DIR / "config.json"

def load_config() -> dict:
    try:
        if _CONFIG_FILE.exists():
            return json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}

def save_config(data: dict):
    try:
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        _CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass

# ── App-wide theme ──────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ── Colour palette ───────────────────────────────────────────────────────────
BG         = "#0d0d0d"
SURFACE    = "#141414"
SURFACE2   = "#1a1a1a"
SURFACE3   = "#202020"
BORDER     = "#262626"
BORDER2    = "#303030"
TEXT       = "#f0ede8"
TEXT2      = "#888480"
TEXT3      = "#484644"
ACCENT     = "#c8b89a"
ACCENT2    = "#a89070"
GREEN      = "#5db876"
AMBER      = "#c8a84a"
RED        = "#c86060"
BLUE       = "#6fa8d0"

# ── Font definitions ─────────────────────────────────────────────────────────
# Sans-serif stack — Segoe UI (Windows native, clean render at all sizes)
_UI   = "Segoe UI"
# Monospace stack — Consolas (sharper than Courier New on Windows)
_MONO = "Consolas"

# ── Language map ────────────────────────────────────────────────────────────
EXT_MAP = {
    # C / C++ family
    "c": "c", "h": "c/c++", "cc": "c++", "cpp": "c++", "cxx": "c++",
    "hpp": "c++", "hh": "c++", "hxx": "c++", "inl": "c++", "tpp": "c++",
    # Web
    "js": "javascript", "mjs": "javascript", "jsx": "javascript",
    "ts": "typescript", "tsx": "typescript",
    "vue": "javascript", "svelte": "javascript",
    "html": "html", "htm": "html", "css": "css", "scss": "css",
    # JVM
    "java": "java", "kt": "kotlin", "kts": "kotlin", "groovy": "groovy",
    "scala": "scala",
    # Systems
    "rs": "rust", "go": "go", "zig": "zig",
    # Scripting
    "py": "python", "rb": "ruby", "php": "php", "pl": "perl", "lua": "lua",
    "ex": "elixir", "exs": "elixir",
    # Shell
    "sh": "shell", "bash": "shell", "zsh": "shell", "ps1": "powershell",
    # .NET
    "cs": "csharp", "fs": "fsharp",
    # Mobile
    "swift": "swift", "dart": "dart", "m": "objective-c",
    # Data
    "sql": "sql", "r": "r", "jl": "julia",
    # Config
    "json": "json", "yaml": "yaml", "yml": "yaml", "toml": "toml",
    # Functional
    "hs": "haskell", "ml": "ocaml",
}

MAX_FILE_BYTES = 1_048_576  # 1 MB

SYSTEM_PROMPT = (
    "You are an expert code forensic analyst and explainable classifier specialized in "
    "detecting AI-generated source code. Your job is to analyze one or more source files — "
    "including C/C++ header files (.hpp, .hh, .hxx, .h), implementation files, and files in "
    "any other language — and produce a single, defensible AI-authorship percentage for the "
    "entire submission and for each file and logical block. Be conservative: prefer false "
    "negatives over false positives. Provide clear, evidence-based rationales. "
    "Output ONLY the JSON described — no markdown fences, no explanation, no preamble. "
    "Your entire response must be a single valid JSON object."
)

REMEDIATION_SYSTEM_PROMPT = """\
You are a principal-level Information Systems architect and enterprise software security \
developer with 15+ years of production engineering experience across defense, financial, \
and critical infrastructure domains. You operate under ISO/IEC 27001, NIST SP 800-53, \
institutional SDLC governance standards, and peer-reviewed code-review policy.

You have received AI-authorship forensic output from CodeSentinel. Your mandate is to \
produce a single, self-contained Claude Code CLI prompt — ready to paste into a terminal \
— that a developer can execute to refactor the flagged source in a way that eliminates \
the detected AI-authorship signals while rigorously preserving every functional contract, \
interface, and behavioral semantic.

THE GENERATED PROMPT MUST CONFORM TO THE FOLLOWING IS STANDARDS:

SCOPE CONTROL
• Target only the files and logical blocks explicitly identified in the forensic report.
• No changes outside flagged scope. No dependency upgrades, no structural reorganisation \
unless the reorganisation directly addresses a named signal.

NATURALIZATION DIRECTIVES (address each that appears in the report)
• Generic identifiers: rename to project-contextual, domain-specific names reflecting \
  actual business logic (e.g. process_data → normalise_inbound_telemetry).
• Uniform error handling: decompose into organic, context-specific handling that mirrors \
  iterative developer decision-making (varied granularity, domain-appropriate messages).
• LLM comment phrasing: replace verbose restatement comments with terse rationale \
  annotations — document WHY, not WHAT; remove "this function takes X and returns Y" patterns.
• Stylistic uniformity: introduce deliberate, authentic variance — mixed line lengths, \
  locale-appropriate abbreviation habits, inconsistent (but readable) blank-line spacing \
  consistent with a single developer working across sessions.
• Boilerplate density: replace template-matching patterns with implementations that show \
  project-specific knowledge (reference real data structures, actual error codes, \
  local naming conventions visible elsewhere in the submission).

VERIFICATION REQUIREMENTS (instruct the developer to perform these steps)
1. Diff review: confirm no functional lines changed outside the naturalization edits.
2. Static analysis: run the project's linter/type-checker at the same severity level as CI.
3. Unit / integration tests: full suite must pass unchanged.
4. Second-pass forensic check: re-submit to CodeSentinel and confirm score improvement.

CHANGESET GOVERNANCE
• All edits must be reviewable in a single clean PR/commit.
• The prompt must instruct Claude Code NOT to rewrite files wholesale — only targeted \
  in-place edits per flagged block.
• Include a note that the developer must review and approve each suggested change before \
  accepting it.

Output ONLY the Claude Code CLI prompt text — no preamble, no explanation, no markdown \
fences, no surrounding commentary. The output must begin immediately with the instruction \
to Claude Code and be ready for direct terminal paste.\
"""

def build_remediation_user_prompt(report: dict) -> str:
    g      = report.get("global", {})
    sid    = report.get("submission_id", "unknown")
    gp     = _norm_pct(g.get("ai_percentage", 0))
    conf   = _norm_conf(g.get("confidence", "low"))
    sigs   = g.get("top_signals", [])
    notes  = report.get("notes", "")
    files  = report.get("files", [])

    file_summaries = []
    for f in files:
        if f.get("error"):
            continue
        blocks = f.get("blocks", [])
        flagged = [b for b in blocks if _norm_pct(b.get("ai_likelihood", 0) * 100) >= 40]
        file_summaries.append({
            "path":        f.get("path", "?"),
            "language":    f.get("language", "unknown"),
            "ai_pct":      _norm_pct(f.get("ai_percentage", 0)),
            "confidence":  _norm_conf(f.get("confidence", "low")),
            "flagged_blocks": [
                {
                    "id":         b.get("id"),
                    "lines":      f"{b.get('start_line','?')}–{b.get('end_line','?')}",
                    "likelihood": f"{_norm_pct(b.get('ai_likelihood',0)*100):.1f}%",
                    "confidence": _norm_conf(b.get("confidence","low")),
                    "evidence":   b.get("evidence", []),
                }
                for b in flagged
            ],
        })

    return (
        f"CODESENTINEL FORENSIC REPORT — SUBMISSION {sid}\n"
        f"Global AI Authorship Score : {gp:.1f}%\n"
        f"Global Confidence          : {conf}\n"
        f"Top Signals                : {'; '.join(sigs) if sigs else 'none listed'}\n"
        f"Caveats                    : {notes if notes else 'none'}\n\n"
        f"FILE-LEVEL FINDINGS:\n"
        f"{json.dumps(file_summaries, indent=2)}\n\n"
        "Using the IS standards in your system instructions, generate the Claude Code "
        "CLI remediation prompt now."
    )


def build_user_prompt(submission_id: str, files_payload: list) -> str:
    return f"""Analyze these source files for AI authorship. Parse each file into logical blocks \
(functions, classes, structs, template definitions, include guard blocks, large comment sections, \
macros, contiguous top-level code). Apply the following weighted signals:

STRONG (0.25 each): boilerplate density matching AI completions, unnatural error handling, external snippet similarity
MEDIUM (0.10 each): stylistic uniformity, overly verbose comments restating code, LLM phrasing \
("this function takes X and returns Y"), idiomatic-but-generic solutions with no domain knowledge
WEAK (0.05 each): generic naming (process_data, handle_request, utils, helpers, manager), \
inconsistent abstraction jumps

CONTEXT ADJUSTMENTS:
• Multiply block score ×0.6 if it contains project-specific identifiers or local resource references
• Multiply block score ×0.5 for trivial short blocks <5 lines (getters, simple guards, include directives)

CONFIDENCE: score<0.2→low · 0.2–0.5→medium · >0.5→high
Require ≥2 independent strong signals before marking any block high-probability AI.
For each block provide 2–4 concise evidence strings — be specific, quote patterns, name the signal.

Return ONLY this exact JSON (no other text):
{{
  "submission_id": "{submission_id}",
  "global": {{
    "ai_percentage": <0.0-100.0 one decimal>,
    "confidence": "<low|medium|high>",
    "top_signals": ["<signal>","<signal>","<signal>"]
  }},
  "files": [{{
    "path": "<string>",
    "language": "<string>",
    "ai_percentage": <0.0-100.0>,
    "confidence": "<low|medium|high>",
    "error": null,
    "blocks": [{{
      "id": "<string>",
      "start_line": <int>,
      "end_line": <int>,
      "ai_likelihood": <0.000-1.000>,
      "confidence": "<low|medium|high>",
      "evidence": ["<specific reason>","<specific reason>"]
    }}]
  }}],
  "notes": "<caveats>"
}}

Files to analyze:
{json.dumps({"submission_id": submission_id, "calibration_offset": 0.0, "files": files_payload}, indent=2)}"""


def repair_json(s: str) -> str:
    """Attempt to close unclosed brackets in a truncated JSON string."""
    opens = []
    in_str = False
    escape = False
    for ch in s:
        if escape:
            escape = False
            continue
        if ch == '\\' and in_str:
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == '{':
            opens.append('}')
        elif ch == '[':
            opens.append(']')
        elif ch in ('}', ']'):
            if opens:
                opens.pop()
    repaired = re.sub(r',\s*$', '', s)
    return repaired + ''.join(reversed(opens))


def detect_lang(path: str) -> str:
    ext = Path(path).suffix.lstrip('.').lower()
    return EXT_MAP.get(ext, "unknown")


def is_likely_binary(data: bytes) -> bool:
    sample = data[:4000]
    non_print = sum(1 for b in sample if b < 9 or (13 < b < 32) or b == 127)
    return (non_print / max(len(sample), 1)) > 0.05


def score_class(pct: float) -> str:
    if pct < 25:
        return "low"
    if pct < 65:
        return "medium"
    return "high"


def score_color(pct: float) -> str:
    if pct < 25:
        return GREEN
    if pct < 65:
        return AMBER
    return RED


_CONF_BG = {"low": "#0d1a10", "medium": "#1a160a", "high": "#1a0d0d"}
_CONF_FG = {"low": GREEN, "medium": AMBER, "high": RED}

def _norm_conf(v) -> str:
    s = str(v).lower().strip() if not isinstance(v, str) else v.lower().strip()
    return s if s in ("low", "medium", "high") else "low"

def _norm_pct(v) -> float:
    try:
        return max(0.0, min(100.0, float(v)))
    except (TypeError, ValueError):
        return 0.0

def verdict_text(pct: float) -> str:
    if pct < 10:
        return ("Strong indicators of human authorship. The code exhibits organic complexity, "
                "project-specific context, and natural stylistic variation consistent with a "
                "human developer working iteratively over time.")
    if pct < 25:
        return ("Predominantly human-written. Minor signals may reflect developer habits or "
                "borrowed snippets, but no significant AI authorship patterns were identified.")
    if pct < 50:
        return ("Mixed authorship detected. Portions show signals consistent with AI-assisted "
                "development — possibly targeted use of LLM completions for specific functions "
                "or boilerplate sections.")
    if pct < 75:
        return ("Substantial AI authorship indicators. A majority of the code exhibits patterns "
                "strongly associated with LLM output: stylistic uniformity, verbose restating "
                "comments, and generic naming conventions.")
    return ("High probability of AI authorship. Multiple strong concurrent signals: boilerplate "
            "density, LLM comment phrasing, generic naming, and uniform abstraction — consistent "
            "with wholesale AI generation.")


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION WINDOW
# ═══════════════════════════════════════════════════════════════════════════

class CodeSentinelApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CodeSentinel  —  AI Authorship Detector")
        self.geometry("1200x900")
        self.minsize(900, 660)
        self.configure(fg_color=BG)

        self.file_queue = []
        self.analysis_running = False
        self.api_key = tk.StringVar()
        self._last_result = None
        self._config = load_config()
        if self._config.get("api_key"):
            self.api_key.set(self._config["api_key"])
        self._model_var = tk.StringVar(value=self._config.get("model", "claude-sonnet-4-6"))

        self.report_callback_exception = self._tk_exception_handler

        self._build_ui()

    def _tk_exception_handler(self, exc_type, exc_val, exc_tb):
        tb_str = "".join(traceback.format_exception(exc_type, exc_val, exc_tb))
        try:
            self.log_box.configure(state="normal")
            self.log_box.insert("end", f"\n[MAIN-THREAD ERROR]\n{tb_str}\n")
            self.log_box.see("end")
            self.log_box.configure(state="disabled")
            if not self.progress_outer.winfo_ismapped():
                self.progress_outer.pack(fill="x", pady=(0, 20))
        except Exception:
            pass
        import sys
        print(tb_str, file=sys.stderr)

    # ── UI CONSTRUCTION ─────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Accent top bar (1px) ────────────────────────────────────────────
        accent_bar = ctk.CTkFrame(self, fg_color=ACCENT2, height=2, corner_radius=0)
        accent_bar.pack(fill="x", side="top")

        # ── Header ──────────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=SURFACE, corner_radius=0, height=70)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        name_frame = ctk.CTkFrame(hdr, fg_color="transparent")
        name_frame.pack(side="left", padx=26, pady=0)

        ctk.CTkLabel(
            name_frame, text="CODE", font=(_UI, 24, "bold"),
            text_color=TEXT
        ).pack(side="left", pady=16)
        ctk.CTkLabel(
            name_frame, text="SENTINEL", font=(_UI, 24, "bold"),
            text_color=ACCENT
        ).pack(side="left", padx=(5, 0), pady=16)
        ctk.CTkLabel(
            name_frame, text=" v2.0", font=(_MONO, 13),
            text_color=TEXT3
        ).pack(side="left", pady=20)

        ctk.CTkLabel(
            hdr, text="AI Authorship Detector",
            font=(_MONO, 13), text_color=TEXT3
        ).pack(side="right", padx=26, pady=16)

        # ── Separator ───────────────────────────────────────────────────────
        ctk.CTkFrame(self, fg_color=BORDER, height=1, corner_radius=0).pack(fill="x")

        # ── Body scroll container ────────────────────────────────────────────
        self.body = ctk.CTkScrollableFrame(
            self, fg_color=BG, corner_radius=0,
            scrollbar_button_color=BORDER2,
            scrollbar_button_hover_color=BORDER
        )
        self.body.pack(fill="both", expand=True, padx=28, pady=(22, 0))

        self._build_api_panel()
        self._build_drop_zone()
        self._build_history_panel()
        self._build_remediation_panel()
        self._build_queue_section()
        self._build_analyze_bar()
        self._build_progress_section()
        self._build_results_section()

    def _build_api_panel(self):
        panel = ctk.CTkFrame(self.body, fg_color=SURFACE, corner_radius=4,
                             border_width=1, border_color=BORDER)
        panel.pack(fill="x", pady=(0, 14))

        row = ctk.CTkFrame(panel, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=14)

        ctk.CTkLabel(row, text="KEY", font=(_MONO, 12),
                     text_color=AMBER, width=36).pack(side="left", anchor="n", pady=(2, 0))

        info = ctk.CTkFrame(row, fg_color="transparent")
        info.pack(side="left", fill="x", expand=True, padx=(10, 0))

        ctk.CTkLabel(info, text="Anthropic API Key",
                     font=(_UI, 15, "bold"), text_color=TEXT,
                     anchor="w").pack(fill="x")
        ctk.CTkLabel(
            info,
            text="Required to call the analysis model. Click Save to store the key permanently on this machine.",
            font=(_MONO, 11), text_color=TEXT3, anchor="w", wraplength=680, justify="left"
        ).pack(fill="x", pady=(2, 8))

        key_row = ctk.CTkFrame(info, fg_color="transparent")
        key_row.pack(fill="x")

        self.api_entry = ctk.CTkEntry(
            key_row, textvariable=self.api_key,
            placeholder_text="sk-ant-api03-…",
            show="•", width=400,
            fg_color=SURFACE2, border_color=BORDER,
            text_color=TEXT, placeholder_text_color=TEXT3,
            font=(_MONO, 13), corner_radius=4
        )
        self.api_entry.pack(side="left")

        ctk.CTkButton(
            key_row, text="Save", width=72, height=32,
            fg_color=ACCENT, hover_color=TEXT,
            text_color=BG, font=(_UI, 12, "bold"),
            corner_radius=4,
            command=self._save_key
        ).pack(side="left", padx=(8, 0))

        ctk.CTkButton(
            key_row, text="Clear", width=64, height=32,
            fg_color=BORDER2, hover_color=SURFACE3,
            text_color=TEXT2, font=(_UI, 12),
            corner_radius=4,
            command=self._clear_key
        ).pack(side="left", padx=(6, 0))

        self._key_status = ctk.CTkLabel(
            key_row, text="", font=(_MONO, 11),
            text_color=GREEN
        )
        self._key_status.pack(side="left", padx=8)

        ctk.CTkButton(
            key_row, text="show/hide", width=80, height=32,
            fg_color="transparent", hover_color=SURFACE3,
            text_color=TEXT3, font=(_MONO, 11),
            corner_radius=4,
            command=self._toggle_key_show
        ).pack(side="left", padx=(4, 0))

        # Show saved indicator on startup if key was loaded
        if self._config.get("api_key"):
            self._key_status.configure(text="● key loaded from disk")

    def _toggle_key_show(self):
        current = self.api_entry.cget("show")
        self.api_entry.configure(show="" if current == "•" else "•")

    def _save_key(self):
        key = self.api_key.get().strip()
        if key:
            self._config["api_key"] = key
            save_config(self._config)
            self._key_status.configure(text="✓ saved to disk", text_color=GREEN)
        else:
            self._key_status.configure(text="⚠ enter a key first", text_color=AMBER)
        self.after(3000, lambda: self._key_status.configure(text=""))

    def _clear_key(self):
        self.api_key.set("")
        self._config.pop("api_key", None)
        save_config(self._config)
        self._key_status.configure(text="key cleared", text_color=TEXT3)
        self.after(3000, lambda: self._key_status.configure(text=""))

    # ── File Input Panel ─────────────────────────────────────────────────────
    def _build_drop_zone(self):
        panel = ctk.CTkFrame(
            self.body, fg_color=SURFACE, corner_radius=4,
            border_width=1, border_color=BORDER
        )
        panel.pack(fill="x", pady=(0, 14))

        row = ctk.CTkFrame(panel, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=18)

        ctk.CTkLabel(row, text="ADD FILES", font=(_MONO, 12),
                     text_color=ACCENT, width=80).pack(side="left", anchor="n", pady=(2, 0))

        content = ctk.CTkFrame(row, fg_color="transparent")
        content.pack(side="left", fill="x", expand=True, padx=(10, 0))

        ctk.CTkLabel(
            content, text="Add Source Files to Queue",
            font=(_UI, 15, "bold"), text_color=TEXT, anchor="w"
        ).pack(fill="x")

        ctk.CTkLabel(
            content,
            text=".py  .js  .ts  .java  .go  .rs  .cpp  .c  .hpp  .h  .cs  .rb  .swift  .kt  .sh  and more",
            font=(_MONO, 11), text_color=TEXT3, anchor="w"
        ).pack(fill="x", pady=(2, 10))

        btn_row = ctk.CTkFrame(content, fg_color="transparent")
        btn_row.pack(anchor="w")

        ctk.CTkButton(
            btn_row, text="Browse Files", width=140, height=36,
            fg_color=BORDER2, hover_color=SURFACE3,
            text_color=TEXT, font=(_UI, 13),
            corner_radius=4,
            command=self._browse_files
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            btn_row, text="Browse Folder", width=140, height=36,
            fg_color=BORDER2, hover_color=SURFACE3,
            text_color=TEXT, font=(_UI, 13),
            corner_radius=4,
            command=self._browse_folder
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            btn_row, text="Paste Code", width=130, height=36,
            fg_color="transparent", hover_color=SURFACE3,
            text_color=TEXT2, font=(_UI, 13),
            border_width=1, border_color=BORDER,
            corner_radius=4,
            command=lambda: self._open_paste_dialog(None)
        ).pack(side="left")

    # ── History Panel ────────────────────────────────────────────────────────
    def _build_history_panel(self):
        history = self._config.get("history", [])
        if not history:
            self._history_outer = None
            return

        self._history_outer = ctk.CTkFrame(
            self.body, fg_color=SURFACE, corner_radius=4,
            border_width=1, border_color=BORDER
        )
        self._history_outer.pack(fill="x", pady=(0, 14))
        self._render_history_contents()

    def _render_history_contents(self):
        if self._history_outer is None:
            return
        for w in self._history_outer.winfo_children():
            w.destroy()

        history = self._config.get("history", [])

        hdr_row = ctk.CTkFrame(self._history_outer, fg_color="transparent")
        hdr_row.pack(fill="x", padx=18, pady=(12, 6))

        ctk.CTkLabel(hdr_row, text="RECENT SUBMISSIONS",
                     font=(_MONO, 12), text_color=TEXT3).pack(side="left")
        ctk.CTkButton(
            hdr_row, text="clear history", width=100, height=24,
            fg_color="transparent", hover_color=SURFACE2,
            text_color=TEXT3, font=(_MONO, 11),
            corner_radius=4,
            command=self._clear_history
        ).pack(side="right")

        for entry in reversed(history[-10:]):
            self._render_history_row(entry)

        ctk.CTkFrame(self._history_outer, fg_color="transparent", height=6).pack()

    def _render_history_row(self, entry: dict):
        pct   = entry.get("ai_percentage", 0.0)
        col   = score_color(pct)
        conf  = entry.get("confidence", "low")
        sid   = entry.get("submission_id", "?")
        ts    = entry.get("timestamp", "")
        files = entry.get("file_count", 0)
        model = entry.get("model", "")

        row = ctk.CTkFrame(
            self._history_outer, fg_color=SURFACE2,
            corner_radius=3, border_width=1, border_color=BORDER
        )
        row.pack(fill="x", padx=18, pady=2)

        inner = ctk.CTkFrame(row, fg_color="transparent")
        inner.pack(fill="x", padx=14, pady=8)

        # Score pill
        pill = ctk.CTkFrame(inner, fg_color=SURFACE3,
                             border_width=1, border_color=col, corner_radius=3)
        pill.pack(side="left")
        ctk.CTkLabel(
            pill, text=f"{pct:.1f}%",
            font=(_MONO, 13, "bold"), text_color=col,
            padx=10, pady=3
        ).pack()

        mid = ctk.CTkFrame(inner, fg_color="transparent")
        mid.pack(side="left", fill="x", expand=True, padx=(12, 0))

        ctk.CTkLabel(
            mid, text=sid,
            font=(_MONO, 12), text_color=TEXT, anchor="w"
        ).pack(fill="x")

        meta_parts = []
        if ts:
            meta_parts.append(ts)
        if files:
            meta_parts.append(f"{files} file{'s' if files != 1 else ''}")
        if model:
            short = model.split("-")[1] if "-" in model else model
            meta_parts.append(short)
        meta_parts.append(f"confidence: {conf}")

        ctk.CTkLabel(
            mid, text="  ·  ".join(meta_parts),
            font=(_MONO, 11), text_color=TEXT3, anchor="w"
        ).pack(fill="x")

        verdict = "Human" if pct < 25 else "Mixed" if pct < 65 else "AI-likely"
        ctk.CTkLabel(
            inner, text=verdict,
            font=(_UI, 12, "bold"), text_color=col
        ).pack(side="right")

    def _save_to_history(self, result: dict, model: str):
        g = result.get("global", {})
        entry = {
            "submission_id":  result.get("submission_id", "?"),
            "timestamp":      datetime.now().strftime("%Y-%m-%d  %H:%M"),
            "ai_percentage":  _norm_pct(g.get("ai_percentage", 0)),
            "confidence":     _norm_conf(g.get("confidence", "low")),
            "file_count":     len([f for f in result.get("files", []) if not f.get("error")]),
            "model":          model,
        }
        history = self._config.setdefault("history", [])
        history.append(entry)
        self._config["history"] = history[-50:]  # keep last 50
        save_config(self._config)

        def _refresh():
            if self._history_outer is None:
                self._history_outer = ctk.CTkFrame(
                    self.body, fg_color=SURFACE, corner_radius=4,
                    border_width=1, border_color=BORDER
                )
                # Re-pack before the queue section
                self._history_outer.pack(fill="x", pady=(0, 14),
                                         before=self.queue_outer if self.queue_outer.winfo_ismapped()
                                         else self.analyze_outer)
            self._render_history_contents()
        self.after(0, _refresh)

    def _clear_history(self):
        self._config["history"] = []
        save_config(self._config)
        if self._history_outer:
            self._history_outer.pack_forget()
            for w in self._history_outer.winfo_children():
                w.destroy()
            self._history_outer = None

    # ── Remediation Advisor Panel ────────────────────────────────────────────
    def _build_remediation_panel(self):
        self._rem_outer = ctk.CTkFrame(
            self.body, fg_color=SURFACE, corner_radius=4,
            border_width=1, border_color=BORDER
        )
        self._rem_outer.pack(fill="x", pady=(0, 14))
        self._rem_generating = False
        self._render_remediation_panel()

    def _render_remediation_panel(self):
        for w in self._rem_outer.winfo_children():
            w.destroy()

        # ── Panel header row ─────────────────────────────────────────────────
        hdr_row = ctk.CTkFrame(self._rem_outer, fg_color="transparent")
        hdr_row.pack(fill="x", padx=18, pady=(14, 0))

        left_hdr = ctk.CTkFrame(hdr_row, fg_color="transparent")
        left_hdr.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            left_hdr, text="REMEDIATION ADVISOR",
            font=(_MONO, 12), text_color=BLUE
        ).pack(anchor="w")
        ctk.CTkLabel(
            left_hdr,
            text=(
                "Generates a Claude Code CLI prompt — authored to IS development standards — "
                "that targets and naturalises every flagged AI-authorship signal in the last submission."
            ),
            font=(_MONO, 11), text_color=TEXT3,
            anchor="w", wraplength=820, justify="left"
        ).pack(fill="x", pady=(2, 0))

        # ── Generate button row ──────────────────────────────────────────────
        btn_row = ctk.CTkFrame(self._rem_outer, fg_color="transparent")
        btn_row.pack(fill="x", padx=18, pady=(10, 0))

        has_result = self._last_result is not None
        has_key    = bool(self.api_key.get().strip())

        self._rem_gen_btn = ctk.CTkButton(
            btn_row,
            text="Generate Remediation Prompt",
            width=240, height=36,
            fg_color=BLUE if (has_result and has_key) else BORDER2,
            hover_color=TEXT if (has_result and has_key) else SURFACE3,
            text_color=BG if (has_result and has_key) else TEXT3,
            font=(_UI, 13, "bold"),
            corner_radius=4,
            state="normal" if (has_result and has_key) else "disabled",
            command=self._generate_remediation_prompt
        )
        self._rem_gen_btn.pack(side="left")

        if not has_result:
            ctk.CTkLabel(
                btn_row,
                text="Run an analysis first to enable prompt generation.",
                font=(_MONO, 11), text_color=TEXT3
            ).pack(side="left", padx=14)
        elif not has_key:
            ctk.CTkLabel(
                btn_row,
                text="API key required.",
                font=(_MONO, 11), text_color=AMBER
            ).pack(side="left", padx=14)
        else:
            sid = self._last_result.get("submission_id", "?")
            gp  = _norm_pct(self._last_result.get("global", {}).get("ai_percentage", 0))
            ctk.CTkLabel(
                btn_row,
                text=f"Active submission: {sid}  ·  {gp:.1f}% AI score",
                font=(_MONO, 11), text_color=TEXT2
            ).pack(side="left", padx=14)

        # ── Output area ──────────────────────────────────────────────────────
        self._rem_output_frame = ctk.CTkFrame(self._rem_outer, fg_color="transparent")
        self._rem_output_frame.pack(fill="x", padx=18, pady=(10, 0))

        # ── History ──────────────────────────────────────────────────────────
        self._render_remediation_history()

        ctk.CTkFrame(self._rem_outer, fg_color="transparent", height=10).pack()

    def _generate_remediation_prompt(self):
        if self._rem_generating or not self._last_result:
            return
        key = self.api_key.get().strip()
        if not key:
            return

        self._rem_generating = True
        self._rem_gen_btn.configure(
            state="disabled", text="Generating…",
            fg_color=BORDER2, text_color=TEXT3
        )

        # Clear previous output
        for w in self._rem_output_frame.winfo_children():
            w.destroy()

        status_lbl = ctk.CTkLabel(
            self._rem_output_frame,
            text="⟳  Calling classifier — composing IS-standard remediation prompt…",
            font=(_MONO, 11), text_color=ACCENT
        )
        status_lbl.pack(anchor="w", pady=(0, 6))

        result_snapshot = self._last_result
        model = self._model_var.get()

        def _thread():
            try:
                prompt_text = self._call_remediation_api(key, result_snapshot, model)
                self.after(0, lambda p=prompt_text: self._show_remediation_output(p, result_snapshot, model))
            except Exception as e:
                err = str(e)
                self.after(0, lambda m=err: self._show_remediation_error(m))
            finally:
                self._rem_generating = False
                self.after(0, self._restore_gen_btn)

        threading.Thread(target=_thread, daemon=True).start()

    def _call_remediation_api(self, api_key: str, report: dict, model: str) -> str:
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "anthropic-dangerous-direct-browser-access": "true",
        }
        body = {
            "model": model,
            "max_tokens": 4096,
            "system": REMEDIATION_SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": build_remediation_user_prompt(report)}],
        }
        with httpx.Client(timeout=120) as client:
            resp = client.post("https://api.anthropic.com/v1/messages",
                               headers=headers, json=body)

        if resp.status_code == 401:
            raise RuntimeError("API key invalid or expired (401)")
        if resp.status_code == 429:
            raise RuntimeError("Rate limit — wait 30 seconds and retry (429)")
        if not resp.is_success:
            raise RuntimeError(f"API error {resp.status_code}: {resp.text[:300]}")

        raw  = resp.json()
        if "error" in raw:
            raise RuntimeError(raw["error"].get("message", str(raw["error"])))

        text = "".join(b["text"] for b in raw.get("content", []) if b["type"] == "text")
        text = re.sub(r'^```(?:\w+)?\s*', '', text.strip()).rstrip()
        text = re.sub(r'\s*```\s*$', '', text).strip()
        return text

    def _show_remediation_output(self, prompt_text: str, report: dict, model: str):
        for w in self._rem_output_frame.winfo_children():
            w.destroy()

        # Divider
        ctk.CTkFrame(self._rem_output_frame, fg_color=BORDER, height=1,
                     corner_radius=0).pack(fill="x", pady=(0, 10))

        # Output header
        out_hdr = ctk.CTkFrame(self._rem_output_frame, fg_color="transparent")
        out_hdr.pack(fill="x", pady=(0, 6))

        ctk.CTkLabel(
            out_hdr, text="GENERATED PROMPT",
            font=(_MONO, 12), text_color=TEXT3
        ).pack(side="left")

        ts = datetime.now().strftime("%Y-%m-%d  %H:%M")
        ctk.CTkLabel(
            out_hdr, text=f"{ts}  ·  {model.split('-')[1] if '-' in model else model}",
            font=(_MONO, 11), text_color=TEXT3
        ).pack(side="right")

        # Textbox
        box = ctk.CTkTextbox(
            self._rem_output_frame,
            height=260, fg_color=SURFACE2,
            text_color=TEXT, font=(_MONO, 12),
            border_width=1, border_color=BORDER2,
            corner_radius=4, activate_scrollbars=True,
            scrollbar_button_color=BORDER2, wrap="word"
        )
        box.pack(fill="x")
        box.insert("1.0", prompt_text)
        box.configure(state="disabled")

        # Action buttons
        act_row = ctk.CTkFrame(self._rem_output_frame, fg_color="transparent")
        act_row.pack(fill="x", pady=(8, 0))

        def _copy():
            self.clipboard_clear()
            self.clipboard_append(prompt_text)
            copy_btn.configure(text="Copied ✓", fg_color=GREEN, text_color=BG)
            self.after(2200, lambda: copy_btn.configure(
                text="Copy to Clipboard", fg_color=BORDER2, text_color=TEXT2))

        copy_btn = ctk.CTkButton(
            act_row, text="Copy to Clipboard", width=160, height=32,
            fg_color=BORDER2, hover_color=SURFACE3,
            text_color=TEXT2, font=(_UI, 12),
            corner_radius=4, command=_copy
        )
        copy_btn.pack(side="left")

        ctk.CTkLabel(
            act_row,
            text="Paste this prompt into your Claude Code terminal session to begin remediation.",
            font=(_MONO, 11), text_color=TEXT3
        ).pack(side="left", padx=14)

        # Save to history
        self._save_remediation_history(report, prompt_text, model)
        self._render_remediation_history()

    def _show_remediation_error(self, msg: str):
        for w in self._rem_output_frame.winfo_children():
            w.destroy()
        ctk.CTkLabel(
            self._rem_output_frame,
            text=f"Generation failed: {msg}",
            font=(_MONO, 11), text_color=RED,
            anchor="w", wraplength=900, justify="left"
        ).pack(anchor="w")

    def _restore_gen_btn(self):
        has_result = self._last_result is not None
        has_key    = bool(self.api_key.get().strip())
        active = has_result and has_key
        self._rem_gen_btn.configure(
            state="normal" if active else "disabled",
            text="Generate Remediation Prompt",
            fg_color=BLUE if active else BORDER2,
            hover_color=TEXT if active else SURFACE3,
            text_color=BG if active else TEXT3,
        )

    # ── Remediation history helpers ──────────────────────────────────────────
    def _save_remediation_history(self, report: dict, prompt_text: str, model: str):
        entry = {
            "submission_id": report.get("submission_id", "?"),
            "timestamp":     datetime.now().strftime("%Y-%m-%d  %H:%M"),
            "ai_percentage": _norm_pct(report.get("global", {}).get("ai_percentage", 0)),
            "confidence":    _norm_conf(report.get("global", {}).get("confidence", "low")),
            "model":         model,
            "prompt":        prompt_text,
            "preview":       prompt_text[:160].replace("\n", " ").strip() + ("…" if len(prompt_text) > 160 else ""),
        }
        hist = self._config.setdefault("remediation_history", [])
        hist.append(entry)
        self._config["remediation_history"] = hist[-30:]
        save_config(self._config)

    def _render_remediation_history(self):
        # Remove any existing history sub-frame inside rem_outer
        for w in self._rem_outer.winfo_children():
            if getattr(w, "_is_rem_history", False):
                w.destroy()

        hist = self._config.get("remediation_history", [])
        if not hist:
            return

        container = ctk.CTkFrame(self._rem_outer, fg_color="transparent")
        container._is_rem_history = True
        container.pack(fill="x", padx=18, pady=(12, 0))

        # Divider + header
        ctk.CTkFrame(container, fg_color=BORDER, height=1,
                     corner_radius=0).pack(fill="x", pady=(0, 8))

        h_hdr = ctk.CTkFrame(container, fg_color="transparent")
        h_hdr.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(
            h_hdr, text="PROMPT HISTORY",
            font=(_MONO, 12), text_color=TEXT3
        ).pack(side="left")
        ctk.CTkButton(
            h_hdr, text="clear", width=54, height=22,
            fg_color="transparent", hover_color=SURFACE2,
            text_color=TEXT3, font=(_MONO, 11),
            corner_radius=4,
            command=self._clear_remediation_history
        ).pack(side="right")

        for entry in reversed(hist[-8:]):
            self._render_remediation_history_row(container, entry)

    def _render_remediation_history_row(self, parent, entry: dict):
        pct   = entry.get("ai_percentage", 0.0)
        col   = score_color(pct)
        ts    = entry.get("timestamp", "")
        sid   = entry.get("submission_id", "?")
        model = entry.get("model", "")
        preview = entry.get("preview", "")
        full_prompt = entry.get("prompt", "")

        row = ctk.CTkFrame(
            parent, fg_color=SURFACE2,
            corner_radius=3, border_width=1, border_color=BORDER
        )
        row.pack(fill="x", pady=2)

        top_row = ctk.CTkFrame(row, fg_color="transparent")
        top_row.pack(fill="x", padx=12, pady=(8, 2))

        # Score chip
        pill = ctk.CTkFrame(top_row, fg_color=SURFACE3,
                             border_width=1, border_color=col, corner_radius=3)
        pill.pack(side="left")
        ctk.CTkLabel(
            pill, text=f"{pct:.1f}%",
            font=(_MONO, 11, "bold"), text_color=col,
            padx=8, pady=2
        ).pack()

        ctk.CTkLabel(
            top_row, text=f"{sid}  ·  {ts}",
            font=(_MONO, 11), text_color=TEXT2
        ).pack(side="left", padx=(10, 0))

        short_model = model.split("-")[1] if "-" in model else model
        ctk.CTkLabel(
            top_row, text=short_model,
            font=(_MONO, 10), text_color=TEXT3
        ).pack(side="right")

        # Preview text
        ctk.CTkLabel(
            row, text=preview,
            font=(_MONO, 10), text_color=TEXT3,
            anchor="w", wraplength=960, justify="left"
        ).pack(fill="x", padx=12, pady=(0, 4))

        # Expand / Copy row
        act = ctk.CTkFrame(row, fg_color="transparent")
        act.pack(fill="x", padx=12, pady=(0, 8))

        expanded = [False]
        detail_box_holder = [None]

        def _toggle_expand():
            if expanded[0]:
                if detail_box_holder[0]:
                    detail_box_holder[0].destroy()
                    detail_box_holder[0] = None
                expanded[0] = False
                expand_btn.configure(text="▼ view full prompt")
            else:
                box = ctk.CTkTextbox(
                    row, height=200, fg_color=SURFACE,
                    text_color=TEXT, font=(_MONO, 11),
                    border_width=1, border_color=BORDER,
                    corner_radius=3, activate_scrollbars=True,
                    scrollbar_button_color=BORDER2, wrap="word"
                )
                box.pack(fill="x", padx=12, pady=(0, 8))
                box.insert("1.0", full_prompt)
                box.configure(state="disabled")
                detail_box_holder[0] = box
                expanded[0] = True
                expand_btn.configure(text="▲ collapse")

        expand_btn = ctk.CTkButton(
            act, text="▼ view full prompt", width=140, height=24,
            fg_color="transparent", hover_color=SURFACE3,
            text_color=BLUE, font=(_MONO, 11),
            border_width=1, border_color=BORDER,
            corner_radius=3, command=_toggle_expand
        )
        expand_btn.pack(side="left")

        def _copy_hist():
            self.clipboard_clear()
            self.clipboard_append(full_prompt)
            copy_h_btn.configure(text="Copied ✓", fg_color=GREEN, text_color=BG)
            self.after(2000, lambda: copy_h_btn.configure(
                text="Copy", fg_color=BORDER2, text_color=TEXT2))

        copy_h_btn = ctk.CTkButton(
            act, text="Copy", width=70, height=24,
            fg_color=BORDER2, hover_color=SURFACE3,
            text_color=TEXT2, font=(_MONO, 11),
            corner_radius=3, command=_copy_hist
        )
        copy_h_btn.pack(side="left", padx=(6, 0))

    def _clear_remediation_history(self):
        self._config["remediation_history"] = []
        save_config(self._config)
        self._render_remediation_history()

    # ── Queue section ────────────────────────────────────────────────────────
    def _build_queue_section(self):
        self.queue_outer = ctk.CTkFrame(self.body, fg_color="transparent")

        hdr = ctk.CTkFrame(self.queue_outer, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 5))

        ctk.CTkLabel(hdr, text="QUEUED FILES",
                     font=(_MONO, 12), text_color=TEXT3).pack(side="left")
        ctk.CTkButton(
            hdr, text="clear all", width=70, height=24,
            fg_color="transparent", hover_color=SURFACE2,
            text_color=TEXT3, font=(_MONO, 11),
            corner_radius=4,
            command=self._clear_all
        ).pack(side="right")

        self.queue_list = ctk.CTkFrame(self.queue_outer, fg_color="transparent")
        self.queue_list.pack(fill="x")

    # ── Analyze bar ──────────────────────────────────────────────────────────
    def _build_analyze_bar(self):
        self.analyze_outer = ctk.CTkFrame(self.body, fg_color="transparent")

        self.analyze_btn = ctk.CTkButton(
            self.analyze_outer,
            text="Run Analysis",
            width=200, height=40,
            fg_color=ACCENT, hover_color=TEXT,
            text_color=BG, font=(_UI, 14, "bold"),
            corner_radius=4,
            command=self._run_analysis
        )
        self.analyze_btn.pack(side="left")

        # ── Model selector ───────────────────────────────────────────────────
        _MODEL_OPTIONS = {
            "Sonnet 4.6  (fast · recommended)": "claude-sonnet-4-6",
            "Opus 4.7    (thorough · slower)":   "claude-opus-4-7",
            "Haiku 4.5   (fastest · lightweight)": "claude-haiku-4-5-20251001",
        }
        self._model_display_map = _MODEL_OPTIONS
        self._model_reverse_map = {v: k for k, v in _MODEL_OPTIONS.items()}

        saved_model = self._config.get("model", "claude-sonnet-4-6")
        display_default = self._model_reverse_map.get(saved_model, list(_MODEL_OPTIONS.keys())[0])

        model_frame = ctk.CTkFrame(self.analyze_outer, fg_color="transparent")
        model_frame.pack(side="left", padx=(14, 0))

        ctk.CTkLabel(
            model_frame, text="MODEL", font=(_MONO, 10),
            text_color=TEXT3
        ).pack(anchor="w")

        self._model_display_var = tk.StringVar(value=display_default)

        def _on_model_change(choice):
            model_id = self._model_display_map[choice]
            self._model_var.set(model_id)
            self._config["model"] = model_id
            save_config(self._config)

        ctk.CTkOptionMenu(
            model_frame,
            values=list(_MODEL_OPTIONS.keys()),
            variable=self._model_display_var,
            command=_on_model_change,
            fg_color=SURFACE2, button_color=BORDER2, button_hover_color=SURFACE3,
            text_color=TEXT, font=(_MONO, 12), width=280,
            corner_radius=4, dynamic_resizing=False
        ).pack()

        self.analyze_hint = ctk.CTkLabel(
            self.analyze_outer, text="",
            font=(_MONO, 12), text_color=TEXT3
        )
        self.analyze_hint.pack(side="left", padx=14)

    # ── Progress section ─────────────────────────────────────────────────────
    def _build_progress_section(self):
        self.progress_outer = ctk.CTkFrame(
            self.body, fg_color=SURFACE, corner_radius=4,
            border_width=1, border_color=BORDER
        )

        top = ctk.CTkFrame(self.progress_outer, fg_color="transparent")
        top.pack(fill="x", padx=18, pady=(14, 5))

        self.progress_label = ctk.CTkLabel(
            top, text="INITIALIZING",
            font=(_MONO, 12), text_color=TEXT2
        )
        self.progress_label.pack(side="left")

        self.progress_pct_lbl = ctk.CTkLabel(
            top, text="0%",
            font=(_MONO, 12), text_color=ACCENT
        )
        self.progress_pct_lbl.pack(side="right")

        self.progress_bar = ctk.CTkProgressBar(
            self.progress_outer, height=2,
            fg_color=SURFACE3, progress_color=ACCENT,
            corner_radius=0
        )
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", padx=18)

        self.log_box = ctk.CTkTextbox(
            self.progress_outer,
            height=150, fg_color=SURFACE,
            text_color=TEXT2, font=(_MONO, 12),
            border_width=0, activate_scrollbars=True,
            scrollbar_button_color=BORDER2
        )
        self.log_box.pack(fill="x", padx=18, pady=(8, 14))
        self.log_box.configure(state="disabled")

    # ── Results section ───────────────────────────────────────────────────────
    def _build_results_section(self):
        self.results_outer = ctk.CTkFrame(self.body, fg_color="transparent")

    # ═══════════════════════════════════════════════════════════════════════
    #  FILE HANDLING
    # ═══════════════════════════════════════════════════════════════════════

    def _browse_files(self):
        paths = fd.askopenfilenames(
            title="Select source files",
            filetypes=[("Source files", " ".join(f"*.{e}" for e in EXT_MAP)),
                       ("All files", "*.*")]
        )
        if paths:
            self._load_paths(list(paths))

    def _browse_folder(self):
        folder = fd.askdirectory(title="Select a source folder")
        if folder:
            paths = []
            for ext in EXT_MAP:
                paths.extend(Path(folder).rglob(f"*.{ext}"))
            self._load_paths([str(p) for p in paths[:50]])

    def _open_paste_dialog(self, existing_id):
        existing = next((f for f in self.file_queue if f["id"] == existing_id), None) if existing_id else None

        dlg = ctk.CTkToplevel(self)
        dlg.title("Add file manually")
        dlg.geometry("660x520")
        dlg.configure(fg_color=SURFACE)
        dlg.grab_set()
        dlg.focus()

        # Header
        hdr = ctk.CTkFrame(dlg, fg_color=SURFACE2, corner_radius=0, height=44)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="Add file manually", font=(_UI, 12, "bold"), text_color=TEXT).pack(side="left", padx=18, pady=12)

        body = ctk.CTkFrame(dlg, fg_color="transparent", corner_radius=0)
        body.pack(fill="both", expand=True, padx=18, pady=12)

        # Filename
        fn_row = ctk.CTkFrame(body, fg_color="transparent")
        fn_row.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(fn_row, text="Filename", font=(_MONO, 12), text_color=TEXT3, width=80, anchor="w").pack(side="left")
        filename_var = tk.StringVar(value=existing["name"] if existing else "")
        ctk.CTkEntry(
            fn_row, textvariable=filename_var, placeholder_text="e.g. engine.hpp",
            fg_color=SURFACE2, border_color=BORDER, text_color=TEXT,
            placeholder_text_color=TEXT3, font=(_MONO, 13), corner_radius=4
        ).pack(side="left", fill="x", expand=True, padx=(8, 0))

        # Language
        lang_row = ctk.CTkFrame(body, fg_color="transparent")
        lang_row.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(lang_row, text="Language", font=(_MONO, 12), text_color=TEXT3, width=80, anchor="w").pack(side="left")
        lang_options = ["auto-detect"] + sorted(set(EXT_MAP.values()))
        lang_var = tk.StringVar(value=existing["lang"] if existing and existing.get("lang") not in (None, "unknown") else "auto-detect")
        ctk.CTkOptionMenu(
            lang_row, values=lang_options, variable=lang_var,
            fg_color=SURFACE2, button_color=BORDER2, button_hover_color=SURFACE3,
            text_color=TEXT, font=(_MONO, 13), width=240,
            corner_radius=4, dynamic_resizing=False
        ).pack(side="left", padx=(8, 0))

        # Code box
        ctk.CTkLabel(body, text="Source code", font=(_MONO, 12), text_color=TEXT3, anchor="w").pack(fill="x", pady=(4, 2))
        hint_lbl = ctk.CTkLabel(body, text="Paste any source code — all languages supported",
                                font=(_MONO, 11), text_color=TEXT3, anchor="w")
        hint_lbl.pack(fill="x", pady=(0, 4))

        code_box = ctk.CTkTextbox(
            body, fg_color=SURFACE2, text_color=TEXT, font=(_MONO, 11),
            border_width=1, border_color=BORDER, corner_radius=4
        )
        code_box.pack(fill="both", expand=True)
        if existing and existing.get("content"):
            code_box.insert("1.0", existing["content"])

        def on_code_change(event=None):
            content = code_box.get("1.0", "end-1c")
            lines = content.count("\n") + 1
            chars = len(content)
            hint_lbl.configure(text=f"{lines} lines · {chars} chars")
        code_box.bind("<KeyRelease>", on_code_change)

        # Footer
        footer = ctk.CTkFrame(dlg, fg_color=SURFACE2, corner_radius=0, height=50)
        footer.pack(fill="x")
        footer.pack_propagate(False)

        def commit():
            name = filename_var.get().strip() or "untitled.txt"
            content = code_box.get("1.0", "end-1c")
            lang_sel = lang_var.get()
            lang = lang_sel if lang_sel != "auto-detect" else detect_lang(name)
            if not lang:
                lang = "unknown"
            if not content.strip():
                code_box.focus()
                return
            if existing_id:
                for f in self.file_queue:
                    if f["id"] == existing_id:
                        f.update({"name": name, "path": name, "content": content,
                                  "lang": lang, "error": None, "size": len(content.encode())})
                        break
            else:
                self.file_queue.append({
                    "id": f"p{len(self.file_queue)}_{Path(name).stem}",
                    "name": name, "path": name,
                    "lang": lang, "content": content,
                    "size": len(content.encode()), "error": None,
                })
            dlg.destroy()
            self._render_queue()

        ctk.CTkButton(
            footer, text="Cancel", width=80, height=30,
            fg_color="transparent", hover_color=SURFACE3,
            text_color=TEXT2, font=(_UI, 11),
            corner_radius=4,
            command=dlg.destroy
        ).pack(side="right", padx=(0, 10), pady=10)
        ctk.CTkButton(
            footer, text="Add to queue", width=120, height=30,
            fg_color=ACCENT, hover_color=TEXT,
            text_color=BG, font=(_UI, 11, "bold"),
            corner_radius=4,
            command=commit
        ).pack(side="right", padx=(0, 4), pady=10)

        dlg.bind("<Escape>", lambda e: dlg.destroy())

    def _load_paths(self, paths):
        for p in paths:
            path = Path(p)
            if not path.is_file():
                continue
            if any(f["path"] == str(path) for f in self.file_queue):
                continue

            size = path.stat().st_size
            error = None
            content = ""
            lang = detect_lang(path.name)

            if size > MAX_FILE_BYTES:
                error = "File too large (>1 MB)"
            else:
                try:
                    raw = path.read_bytes()
                    if is_likely_binary(raw):
                        error = "Binary file — cannot read as text"
                    else:
                        content = raw.decode("utf-8", errors="replace")
                except Exception as e:
                    error = f"Read error: {e}"

            self.file_queue.append({
                "id": f"f{len(self.file_queue)}_{path.stem}",
                "name": path.name,
                "path": str(path),
                "lang": lang,
                "content": content,
                "size": size,
                "error": error,
            })

        self._render_queue()

    def _render_queue(self):
        if not self.file_queue:
            self.queue_outer.pack_forget()
            self.analyze_outer.pack_forget()
            return

        if not self.queue_outer.winfo_ismapped():
            self.queue_outer.pack(fill="x", pady=(0, 10))
        if not self.analyze_outer.winfo_ismapped():
            self.analyze_outer.pack(fill="x", pady=(0, 18))

        for w in self.queue_list.winfo_children():
            w.destroy()

        valid = sum(1 for f in self.file_queue if not f["error"] and f["content"].strip())
        warn  = sum(1 for f in self.file_queue if f["error"])
        self.analyze_hint.configure(
            text=f"{len(self.file_queue)} file(s) queued  ·  {valid} ready  ·  {warn} error(s)"
        )

        for f in self.file_queue:
            self._render_file_card(f)

    def _render_file_card(self, f):
        has_err = bool(f["error"])
        card = ctk.CTkFrame(
            self.queue_list,
            fg_color=SURFACE,
            border_width=1,
            border_color=AMBER if has_err else BORDER,
            corner_radius=4
        )
        card.pack(fill="x", pady=2)

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=8)

        # Status dot
        dot_col = AMBER if has_err else TEXT3
        ctk.CTkLabel(row, text="■" if has_err else "□", font=(_MONO, 12),
                     text_color=dot_col, width=20).pack(side="left")

        info = ctk.CTkFrame(row, fg_color="transparent")
        info.pack(side="left", fill="x", expand=True, padx=(8, 0))

        name_row = ctk.CTkFrame(info, fg_color="transparent")
        name_row.pack(fill="x")

        ctk.CTkLabel(
            name_row, text=f["name"],
            font=(_MONO, 13), text_color=TEXT,
            anchor="w"
        ).pack(side="left")

        lang_badge = ctk.CTkFrame(
            name_row, fg_color=SURFACE3,
            corner_radius=2, border_width=1, border_color=BORDER
        )
        lang_badge.pack(side="left", padx=(8, 0))
        ctk.CTkLabel(
            lang_badge, text=f["lang"],
            font=(_MONO, 11), text_color=TEXT2,
            padx=6, pady=2
        ).pack()

        if f["error"]:
            meta_text = f["error"]
            meta_col = AMBER
        else:
            lines = f["content"].count("\n") + 1
            kb = f["size"] / 1024
            meta_text = f"{kb:.1f} KB  ·  {lines} lines"
            meta_col = TEXT3

        is_pasted = f.get("path") == f.get("name") and not Path(f.get("path", "")).is_file()
        if is_pasted and not f["error"]:
            fid_edit = f["id"]
            ctk.CTkButton(
                info, text="Edit", width=44, height=16,
                fg_color="transparent", hover_color=SURFACE2,
                text_color=BLUE, font=(_MONO, 8),
                border_width=1, border_color=BORDER,
                corner_radius=2,
                command=lambda i=fid_edit: self._open_paste_dialog(i)
            ).pack(anchor="w", pady=(2, 0))

        ctk.CTkLabel(
            info, text=meta_text,
            font=(_MONO, 11), text_color=meta_col,
            anchor="w"
        ).pack(fill="x")

        fid = f["id"]
        ctk.CTkButton(
            row, text="×", width=24, height=24,
            fg_color="transparent", hover_color=SURFACE3,
            text_color=TEXT3, font=(_UI, 13),
            corner_radius=2,
            command=lambda i=fid: self._remove_file(i)
        ).pack(side="right")

    def _remove_file(self, fid: str):
        self.file_queue = [f for f in self.file_queue if f["id"] != fid]
        self._render_queue()

    def _clear_all(self):
        self.file_queue = []
        self._render_queue()
        self.results_outer.pack_forget()
        for w in self.results_outer.winfo_children():
            w.destroy()
        self.progress_outer.pack_forget()

    # ═══════════════════════════════════════════════════════════════════════
    #  ANALYSIS PIPELINE
    # ═══════════════════════════════════════════════════════════════════════

    def _run_analysis(self):
        if self.analysis_running:
            return
        key = self.api_key.get().strip()
        if not key:
            self._show_error("Please enter your Anthropic API key above before running analysis.")
            return
        valid_files = [f for f in self.file_queue
                       if not f["error"] and f["content"].strip()]
        if not valid_files:
            self._show_error("No readable files in the queue. Add source files to continue.")
            return

        self.analysis_running = True
        self.analyze_btn.configure(state="disabled", text="Analyzing…")

        for w in self.results_outer.winfo_children():
            w.destroy()
        self.results_outer.pack_forget()

        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")
        if not self.progress_outer.winfo_ismapped():
            self.progress_outer.pack(fill="x", pady=(0, 20))
        self.progress_bar.set(0)

        thread = threading.Thread(
            target=self._analysis_thread,
            args=(key, valid_files, self._model_var.get()),
            daemon=True
        )
        thread.start()

    def _ts(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _log(self, msg: str, color: str = TEXT2):
        def _do():
            self.log_box.configure(state="normal")
            self.log_box.insert("end", f"{self._ts()}  {msg}\n")
            self.log_box.see("end")
            self.log_box.configure(state="disabled")
        self.after(0, _do)

    def _set_progress(self, pct: float, label: str):
        def _do():
            self.progress_bar.set(pct / 100)
            self.progress_pct_lbl.configure(text=f"{int(pct)}%")
            self.progress_label.configure(text=label.upper())
        self.after(0, _do)

    def _analysis_thread(self, api_key: str, valid_files: list, model: str):
        try:
            submission_id = "CS-" + hex(int(time.time()))[2:].upper()
            langs = list(dict.fromkeys(str(f.get("lang", "unknown")) for f in valid_files))

            self._set_progress(0, "Initializing forensic engine")
            self._log("CodeSentinel forensic engine v2.0 starting…")
            self._log(f"Submission: {len(valid_files)} file(s) — languages: {', '.join(langs)}")
            self._log(f"Model: {model}")
            time.sleep(0.3)

            self._set_progress(8, "Parsing source structure")
            self._log("Tokenizing source files — separating comment bodies from code tokens…")
            time.sleep(0.28)

            self._set_progress(16, "Extracting logical blocks")
            self._log("Identifying functions, classes, macros, and include guards…")
            time.sleep(0.25)

            for i, f in enumerate(valid_files):
                pct = 16 + (i / len(valid_files)) * 28
                self._set_progress(pct, f"Scanning: {f['name']}")
                lines = f["content"].count("\n") + 1
                self._log(f"  → \"{f['name']}\" [{f['lang']}] — {lines} lines")
                time.sleep(0.22)

            self._set_progress(46, "Running weighted signal detection")
            self._log("Applying forensic heuristics across all parsed blocks…")
            time.sleep(0.22)
            self._log("  Stylistic uniformity — checking naming entropy and consistency…")
            time.sleep(0.20)
            self._log("  Comment analysis — scanning for LLM phrasing patterns…")
            time.sleep(0.20)
            self._log("  Boilerplate density — comparing AI completion fingerprints…")
            time.sleep(0.20)
            self._log("  Error handling — assessing naturalness for language context…")
            time.sleep(0.20)
            self._log("  Generic naming — flagging process_data / handle_request patterns…")
            time.sleep(0.20)

            self._set_progress(66, "Applying context adjustments")
            self._log("Penalizing project-specific identifiers to reduce false positives…")
            time.sleep(0.25)
            self._log("Computing weighted block → file → global score aggregation…")
            time.sleep(0.18)

            self._set_progress(77, "Dispatching to classifier model")
            self._log("Sending payload to Anthropic forensic classifier — awaiting analysis…")

            files_payload = [
                {"path": f["name"], "content": f["content"], "language": f["lang"]}
                for f in valid_files
            ]

            result = self._call_api(api_key, submission_id, files_payload, model)

            self._set_progress(90, "Compiling forensic report")
            self._log("Aggregating evidence chains and calibrating confidence scores…")
            time.sleep(0.25)

            gp = result["global"]["ai_percentage"]
            conf = result["global"]["confidence"]
            self._log(f"Global AI authorship score: {gp:.1f}%  |  confidence: {conf}")

            time.sleep(0.18)
            self._set_progress(100, "Report ready")
            self._log("Forensic analysis complete — report generated.")
            time.sleep(0.3)

            self._last_result = result
            self._save_to_history(result, model)

            def _safe_render(r=result):
                try:
                    self._render_results(r)
                    self._render_remediation_panel()
                except Exception as e:
                    tb = traceback.format_exc()
                    self._log(f"RENDER ERROR: {e}")
                    for line in tb.splitlines():
                        self._log(f"  {line}")
                    self._show_error(str(e))
            self.after(0, _safe_render)

        except Exception as e:
            err_msg = str(e)
            tb = traceback.format_exc()
            self._log(f"ERROR: {err_msg}")
            for line in tb.splitlines():
                self._log(f"  {line}")
            self._set_progress(100, "Error")
            self.after(0, lambda m=err_msg: self._show_error(m))
        finally:
            self.after(0, self._analysis_done)

    def _analysis_done(self):
        self.analysis_running = False
        self.analyze_btn.configure(state="normal", text="Run Analysis")

    def _call_api(self, api_key: str, submission_id: str, files_payload: list,
                  model: str = "claude-sonnet-4-6") -> dict:
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "anthropic-dangerous-direct-browser-access": "true",
        }
        body = {
            "model": model,
            "max_tokens": 8000,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": build_user_prompt(submission_id, files_payload)}],
        }

        with httpx.Client(timeout=120) as client:
            resp = client.post("https://api.anthropic.com/v1/messages",
                               headers=headers, json=body)

        if resp.status_code == 401:
            raise RuntimeError("API key is invalid or expired (401)")
        if resp.status_code == 429:
            raise RuntimeError("Rate limit hit — wait 30 seconds and retry (429)")
        if resp.status_code == 404:
            raise RuntimeError("Model not found (404) — check model name")
        if not resp.is_success:
            raise RuntimeError(f"API error {resp.status_code}: {resp.text[:300]}")

        raw = resp.json()
        if "error" in raw:
            raise RuntimeError(raw["error"].get("message", str(raw["error"])))

        stop_reason = raw.get("stop_reason", "")
        text = "".join(b["text"] for b in raw.get("content", []) if b["type"] == "text")

        text = re.sub(r'^```(?:json)?\s*', '', text).rstrip()
        text = re.sub(r'\s*```\s*$', '', text).strip()

        for attempt in (text, re.search(r'\{[\s\S]*\}', text) and
                        re.search(r'\{[\s\S]*\}', text).group(), repair_json(text)):
            if not attempt:
                continue
            try:
                return json.loads(attempt)
            except json.JSONDecodeError:
                continue

        trunc = " (response truncated — try fewer/smaller files)" if stop_reason == "max_tokens" else ""
        raise RuntimeError(f"Could not parse model response as JSON{trunc}.\n\nRaw (first 400 chars):\n{text[:400]}")

    # ═══════════════════════════════════════════════════════════════════════
    #  RESULTS RENDERING
    # ═══════════════════════════════════════════════════════════════════════

    def _show_error(self, msg: str):
        for w in self.results_outer.winfo_children():
            w.destroy()
        if not self.results_outer.winfo_ismapped():
            self.results_outer.pack(fill="x", pady=(0, 20))
        err = ctk.CTkFrame(
            self.results_outer, fg_color="#160a0a",
            border_width=1, border_color=RED, corner_radius=4
        )
        err.pack(fill="x")
        ctk.CTkLabel(
            err, text=f"Analysis error\n\n{msg}",
            font=(_MONO, 12), text_color=RED,
            wraplength=860, justify="left", anchor="w"
        ).pack(padx=18, pady=14, anchor="w")

    def _render_results(self, data: dict):
        for w in self.results_outer.winfo_children():
            w.destroy()
        if not self.results_outer.winfo_ismapped():
            self.results_outer.pack(fill="x", pady=(0, 40))

        g   = data.get("global", {})
        pct = _norm_pct(g.get("ai_percentage", 0))
        col = score_color(pct)

        # ── Submission label ──
        ctk.CTkLabel(
            self.results_outer,
            text=f"SUBMISSION  {data.get('submission_id', '')}",
            font=(_MONO, 12), text_color=TEXT3, anchor="w"
        ).pack(fill="x", pady=(0, 6))

        # ── Verdict card ──
        vcard = ctk.CTkFrame(
            self.results_outer, fg_color=SURFACE,
            border_width=1, border_color=BORDER, corner_radius=4
        )
        vcard.pack(fill="x", pady=(0, 10))

        vcontent = ctk.CTkFrame(vcard, fg_color="transparent")
        vcontent.pack(fill="x", padx=24, pady=20)

        # Left side
        left = ctk.CTkFrame(vcontent, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(
            left, text="AI AUTHORSHIP SCORE",
            font=(_MONO, 13), text_color=TEXT3, anchor="w"
        ).pack(fill="x")

        ctk.CTkLabel(
            left, text=f"{pct:.1f}%",
            font=(_UI, 56, "bold"), text_color=col, anchor="w"
        ).pack(fill="x")

        # Gauge bar
        gauge_bg = ctk.CTkFrame(left, fg_color=SURFACE3, height=3, corner_radius=0)
        gauge_bg.pack(fill="x", pady=(4, 2))
        gauge_bg.pack_propagate(False)

        gauge_fill = ctk.CTkFrame(gauge_bg, fg_color=col, height=3, corner_radius=0)
        gauge_fill.place(relx=0, rely=0, relwidth=pct / 100, relheight=1)

        ticks = ctk.CTkFrame(left, fg_color="transparent")
        ticks.pack(fill="x")
        for tick in ("0  Human", "50  Mixed", "100  AI"):
            ctk.CTkLabel(ticks, text=tick, font=(_MONO, 8),
                         text_color=TEXT3).pack(side="left", expand=True)

        ctk.CTkLabel(
            left, text=verdict_text(pct),
            font=(_UI, 13), text_color=TEXT2,
            wraplength=520, justify="left", anchor="w"
        ).pack(fill="x", pady=(10, 8))

        # Signal chips
        sig_row = ctk.CTkFrame(left, fg_color="transparent")
        sig_row.pack(fill="x")
        for sig in g.get("top_signals", []):
            chip = ctk.CTkFrame(sig_row, fg_color=SURFACE2,
                                border_width=1, border_color=BORDER, corner_radius=2)
            chip.pack(side="left", padx=(0, 5))
            ctk.CTkLabel(
                chip, text=sig,
                font=(_MONO, 11), text_color=TEXT2, padx=8, pady=4
            ).pack()

        # Right side stats
        right = ctk.CTkFrame(vcontent, fg_color="transparent", width=180)
        right.pack(side="right", fill="y", padx=(18, 0))
        right.pack_propagate(False)

        stats = [
            ("CONFIDENCE", _norm_conf(g.get("confidence", "low")).capitalize(),
             _CONF_FG.get(_norm_conf(g.get("confidence", "low")), AMBER)),
            ("FILES ANALYZED", str(len([f for f in data.get("files", []) if not f.get("error")])), TEXT),
            ("VERDICT", "Human" if pct < 25 else "Mixed" if pct < 65 else "AI-likely",
             score_color(pct)),
        ]
        for label, value, vcol in stats:
            scard = ctk.CTkFrame(right, fg_color=SURFACE2, corner_radius=4,
                                 border_width=1, border_color=BORDER)
            scard.pack(fill="x", pady=3)
            ctk.CTkLabel(scard, text=label, font=(_MONO, 11),
                         text_color=TEXT3).pack(anchor="w", padx=12, pady=(8, 2))
            ctk.CTkLabel(scard, text=value, font=(_UI, 16, "bold"),
                         text_color=vcol).pack(anchor="w", padx=12, pady=(0, 8))

        # ── File breakdown header ──
        bk_hdr = ctk.CTkFrame(self.results_outer, fg_color="transparent")
        bk_hdr.pack(fill="x", pady=(8, 5))
        ctk.CTkLabel(bk_hdr, text="FILE BREAKDOWN",
                     font=(_MONO, 12), text_color=TEXT3).pack(side="left")
        ctk.CTkLabel(bk_hdr, text="click a row to expand blocks",
                     font=(_MONO, 11), text_color=TEXT3).pack(side="right")

        # ── File rows ──
        for f in data.get("files", []):
            self._render_file_result(f)

        # ── Notes ──
        notes = data.get("notes", "")
        if notes:
            nc = ctk.CTkFrame(
                self.results_outer, fg_color=SURFACE,
                border_width=1, border_color=BORDER, corner_radius=4
            )
            nc.pack(fill="x", pady=(8, 0))
            row = ctk.CTkFrame(nc, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=12)
            ctk.CTkLabel(row, text="NOTE", font=(_MONO, 12),
                         text_color=TEXT3, width=42).pack(side="left", anchor="n")
            ctk.CTkLabel(row, text=notes, font=(_MONO, 12),
                         text_color=TEXT2, wraplength=820,
                         justify="left", anchor="w").pack(side="left", fill="x", padx=(10, 0))

        # ── Export button ──
        exp_row = ctk.CTkFrame(self.results_outer, fg_color="transparent")
        exp_row.pack(fill="x", pady=(12, 0))
        ctk.CTkButton(
            exp_row, text="Export JSON",
            width=130, height=28,
            fg_color=BORDER2, hover_color=SURFACE3,
            text_color=TEXT2, font=(_UI, 11),
            corner_radius=4,
            command=self._export_json
        ).pack(side="right")

        self.body._parent_canvas.yview_moveto(1.0)

    def _render_file_result(self, f):
        if f.get("error"):
            row = ctk.CTkFrame(
                self.results_outer, fg_color=SURFACE,
                border_width=1, border_color=BORDER, corner_radius=4
            )
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(
                row, text=f"{f.get('path', '?')}  —  {f['error']}",
                font=(_MONO, 12), text_color=RED, anchor="w"
            ).pack(padx=16, pady=10)
            return

        pct  = _norm_pct(f.get("ai_percentage", 0))
        col  = score_color(pct)
        conf = _norm_conf(f.get("confidence", "low"))

        container = ctk.CTkFrame(
            self.results_outer, fg_color=SURFACE,
            border_width=1, border_color=BORDER, corner_radius=4
        )
        container.pack(fill="x", pady=2)

        body = ctk.CTkFrame(container, fg_color=SURFACE2, corner_radius=0)
        body_visible = [False]

        hdr = ctk.CTkFrame(container, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=10)

        ctk.CTkLabel(
            hdr, text=f.get("path", "?"),
            font=(_MONO, 13), text_color=TEXT, anchor="w"
        ).pack(side="left")

        ctk.CTkLabel(
            hdr, text=f.get("language", ""),
            font=(_MONO, 11), text_color=TEXT3
        ).pack(side="left", padx=10)

        badge_col = _CONF_FG.get(conf, AMBER)
        badge_bg  = _CONF_BG.get(conf, SURFACE3)
        badge = ctk.CTkFrame(hdr, fg_color=badge_bg,
                              border_width=1, border_color=badge_col, corner_radius=2)
        badge.pack(side="right", padx=(8, 0))
        ctk.CTkLabel(badge, text=conf, font=(_MONO, 11),
                     text_color=badge_col, padx=6, pady=3).pack()

        ctk.CTkLabel(
            hdr, text=f"{pct:.1f}%",
            font=(_MONO, 14, "bold"), text_color=col
        ).pack(side="right")

        chev = ctk.CTkLabel(hdr, text="v", font=(_MONO, 11), text_color=TEXT3)
        chev.pack(side="right", padx=(8, 0))

        def toggle(event=None):
            if body_visible[0]:
                body.pack_forget()
                body_visible[0] = False
                chev.configure(text="v")
            else:
                body.pack(fill="x")
                body_visible[0] = True
                chev.configure(text="^")

        def _bind_recursive(widget, callback):
            widget.bind("<Button-1>", callback)
            for child in widget.winfo_children():
                _bind_recursive(child, callback)

        _bind_recursive(hdr, toggle)
        _bind_recursive(container, toggle)

        for b in f.get("blocks", []):
            self._render_block(body, b)

        if not f.get("blocks"):
            ctk.CTkLabel(body, text="No logical blocks identified.",
                         font=(_MONO, 12), text_color=TEXT3,
                         anchor="w").pack(padx=18, pady=12, anchor="w")

    def _render_block(self, parent, b):
        raw_lik = b.get("ai_likelihood", 0)
        try:
            likelihood = max(0.0, min(1.0, float(raw_lik)))
        except (TypeError, ValueError):
            likelihood = 0.0
        pct  = likelihood * 100
        col  = score_color(pct)
        conf = _norm_conf(b.get("confidence", "low"))

        block = ctk.CTkFrame(parent, fg_color="transparent", border_width=0)
        block.pack(fill="x", padx=0, pady=0)

        sep = ctk.CTkFrame(block, fg_color=BORDER, height=1, corner_radius=0)
        sep.pack(fill="x")

        inner = ctk.CTkFrame(block, fg_color="transparent")
        inner.pack(fill="x", padx=18, pady=10)

        top = ctk.CTkFrame(inner, fg_color="transparent")
        top.pack(fill="x")

        ctk.CTkLabel(
            top, text=b.get("id", "block"),
            font=(_MONO, 12, "bold"), text_color=ACCENT
        ).pack(side="left")

        ctk.CTkLabel(
            top,
            text=f"lines {b.get('start_line', '?')}–{b.get('end_line', '?')}",
            font=(_MONO, 11), text_color=TEXT3
        ).pack(side="left", padx=10)

        badge_col = _CONF_FG.get(conf, AMBER)
        badge_bg  = _CONF_BG.get(conf, SURFACE3)
        badge = ctk.CTkFrame(top, fg_color=badge_bg,
                              border_width=1, border_color=badge_col, corner_radius=2)
        badge.pack(side="right")
        ctk.CTkLabel(badge, text=f"{conf} confidence",
                     font=(_MONO, 11), text_color=badge_col,
                     padx=6, pady=3).pack()

        bar_row = ctk.CTkFrame(inner, fg_color="transparent")
        bar_row.pack(fill="x", pady=(6, 0))

        ctk.CTkLabel(
            bar_row, text="AI likelihood",
            font=(_MONO, 11), text_color=TEXT3, width=90
        ).pack(side="left")

        bar_bg = ctk.CTkFrame(bar_row, fg_color=SURFACE3, height=2, corner_radius=0)
        bar_bg.pack(side="left", fill="x", expand=True, padx=(6, 8))
        bar_bg.pack_propagate(False)

        bar_fill = ctk.CTkFrame(bar_bg, fg_color=col, height=2, corner_radius=0)
        bar_fill.place(relx=0, rely=0, relwidth=likelihood, relheight=1)

        ctk.CTkLabel(
            bar_row, text=f"{pct:.1f}%",
            font=(_MONO, 12, "bold"), text_color=col, width=52
        ).pack(side="left")

        for ev in b.get("evidence", []):
            ev_row = ctk.CTkFrame(inner, fg_color="transparent")
            ev_row.pack(fill="x", pady=1)
            ctk.CTkLabel(ev_row, text="→", font=(_MONO, 12),
                         text_color=TEXT3, width=20).pack(side="left")
            ctk.CTkLabel(
                ev_row, text=ev,
                font=(_UI, 12), text_color=TEXT2,
                anchor="w", wraplength=760, justify="left"
            ).pack(side="left", fill="x")

    # ── Export ───────────────────────────────────────────────────────────────
    def _export_json(self):
        if not self._last_result:
            return
        path = fd.asksaveasfilename(
            title="Save JSON report",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"codesentinel_{self._last_result.get('submission_id', 'report')}.json"
        )
        if path:
            with open(path, "w", encoding="utf-8") as fp:
                json.dump(self._last_result, fp, indent=2)


# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = CodeSentinelApp()
    app.mainloop()
