# CodeSentinel — AI Authorship Detector
## Executable Python Application  ·  v2.0

---

## Language Decision

**Python 3.11+ was chosen** over the alternatives for these reasons:

| Option | Rejected because |
|---|---|
| Electron / Node.js | 150–300 MB runtime overhead, browser sandbox limits direct file access |
| C# / WPF | Windows-only without Avalonia rewrite; heavier IDE dependency |
| Java / JavaFX | JVM startup latency, verbose for a single-tool app |
| Rust / Tauri | Excellent choice for production but overkill for a single-developer forensic tool |
| **Python + CustomTkinter** | ✅ Native GUI, rich stdlib file access, async HTTP, single `.exe` via PyInstaller |

Python's key advantages for *this specific domain*:
- `pathlib` + `os` for unrestricted filesystem traversal (no browser sandboxing)
- `httpx` for synchronous + async HTTP with proper timeout/retry
- `ast` module available for future language-specific Python block parsing
- `threading` for non-blocking UI during long API calls
- `PyInstaller` produces a cross-platform distributable with zero user setup

---

## Requirements

```
Python 3.11 or 3.12
customtkinter >= 5.2
httpx >= 0.27
pyinstaller >= 6.0   (build only)
tkinterdnd2          (optional — enables native drag-and-drop on Windows/macOS)
```

Install dependencies:
```bash
pip install customtkinter httpx pyinstaller tkinterdnd2
```

---

## Running from source

```bash
python codesentinel.py
```

---

## Building the executable

### Windows / macOS / Linux — folder distribution (recommended)
```bash
pyinstaller codesentinel.spec
# Output: dist/CodeSentinel/CodeSentinel.exe   (Windows)
#         dist/CodeSentinel/CodeSentinel        (macOS / Linux)
```

### Single-file executable (slower startup, easier distribution)
Edit `codesentinel.spec` and change:
```python
onefile = True   # set this in the EXE() call
```
Then:
```bash
pyinstaller --onefile --windowed codesentinel.py
```

### macOS .app bundle
```bash
pyinstaller --windowed --name CodeSentinel \
    --add-data "$(python -c 'import customtkinter; import os; print(os.path.dirname(customtkinter.__file__))'):customtkinter" \
    codesentinel.py
```

### Adding an icon
Place `assets/icon.ico` (Windows) or `assets/icon.icns` (macOS) in the project folder,
then uncomment the `icon=` line in `codesentinel.spec`.

---


## Usage

1. Launch `CodeSentinel`
2. Enter your Anthropic API key (`sk-ant-api03-…`) in the key panel
3. Drag and drop source files onto the drop zone — or click **Browse files** / **Browse folder**
4. Supported extensions: `.py .js .ts .java .go .rs .cpp .c .hpp .hh .hxx .h .inl .cs .rb .swift .kt .sh .sql` and 30+ more
5. Click **Run Forensic Analysis**
6. Review the verdict card, per-file scores, and per-block evidence
7. Click **Export JSON report** to save the full auditable result

---

## Architecture

```
codesentinel.py          Main application (single file, ~600 lines)
  ├── CodeSentinelApp    CustomTkinter CTk root window
  │   ├── _build_api_panel()      API key entry with session storage
  │   ├── _build_drop_zone()      File drag-and-drop target
  │   ├── _build_queue_section()  Queued file cards
  │   ├── _build_analyze_bar()    Run button + status hint
  │   ├── _build_progress_section() Live log + progress bar
  │   └── _build_results_section()  Verdict card + file/block breakdown
  │
  ├── _analysis_thread()   Runs in background thread (non-blocking UI)
  ├── _call_api()          httpx POST to Anthropic /v1/messages
  └── repair_json()        Fallback JSON parser for truncated responses

codesentinel.spec        PyInstaller build configuration
assets/                  (optional) icon.ico / icon.icns
```

---

## Forensic signals detected

| Signal | Weight | Category |
|---|---|---|
| Boilerplate density matching AI completions | 0.25 | Strong |
| Unnatural error handling for context | 0.25 | Strong |
| External snippet similarity | 0.25 | Strong |
| Stylistic uniformity across blocks | 0.10 | Medium |
| Overly verbose comments restating code | 0.10 | Medium |
| LLM phrasing ("this function takes X…") | 0.10 | Medium |
| Idiomatic-but-generic solutions | 0.10 | Medium |
| Generic naming (process_data, handle_request) | 0.05 | Weak |
| Inconsistent abstraction jumps | 0.05 | Weak |

Context adjustments:
- Project-specific identifiers → score × 0.6
- Trivial blocks < 5 lines → score × 0.5

---

## Output JSON schema

```json
{
  "submission_id": "CS-XXXXXXXX",
  "global": {
    "ai_percentage": 42.3,
    "confidence": "medium",
    "top_signals": ["Boilerplate density", "LLM comment phrasing", "Generic naming"]
  },
  "files": [{
    "path": "main.cpp",
    "language": "c++",
    "ai_percentage": 61.0,
    "confidence": "medium",
    "error": null,
    "blocks": [{
      "id": "fn_process_data",
      "start_line": 14,
      "end_line": 38,
      "ai_likelihood": 0.720,
      "confidence": "high",
      "evidence": [
        "Function name 'process_data' matches common AI completion pattern",
        "Comment block restates parameter types verbatim — typical LLM docstring style"
      ]
    }]
  }],
  "notes": "Conservative estimate. Similarity matches are supporting evidence only."
}
```
