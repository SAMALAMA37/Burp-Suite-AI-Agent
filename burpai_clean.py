# -*- coding: utf-8 -*-
"""
Burp AI Agent - Modernized + Beautified + Robust

Architecture:
- Native OpenAI function/tool calling with prose-JSON fallback in BOTH directions
- Multi-turn ConversationState with proper role="tool" messages and compaction
- ToolRegistry with formal JSON schemas
- ReAct agent loop with signature-based dedup, continue-flag handling
- Retry with exponential backoff on 429/5xx
- Reasoning-field fallback for o1/r1/dots-studio style models
- GitHub-dark themed UI with status bar, chat bubbles, grouped settings
"""
from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import (JPanel, JButton, JTextField, JTextArea, JScrollPane,
                         JTabbedPane, JLabel, JEditorPane, JSplitPane,
                         JOptionPane, JCheckBox, SwingUtilities, BorderFactory,
                         Box, BoxLayout, JSeparator, SwingConstants)
from javax.swing.border import TitledBorder, EmptyBorder, LineBorder, CompoundBorder
from javax.swing.text.html import HTMLEditorKit
from java.awt import (BorderLayout, GridBagLayout, GridBagConstraints, Insets,
                      Color, Font, Dimension, FlowLayout, Component, Cursor)
from java.awt.event import ActionListener, MouseAdapter
from java.net import URL
import os, json, time, re, uuid, threading, traceback
import java.io

try:
    from urllib2 import Request, urlopen, HTTPError, URLError
except ImportError:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError

try:
    _string_types = basestring
except NameError:
    _string_types = str


# ============================================================
#  Theme
# ============================================================
class Theme(object):
    BG_ROOT      = Color(0x0d1117)
    BG_SURFACE   = Color(0x161b22)
    BG_ELEVATED  = Color(0x21262d)
    BG_HOVER     = Color(0x30363d)
    BG_INPUT     = Color(0x0d1117)
    BORDER       = Color(0x30363d)
    BORDER_LIGHT = Color(0x484f58)
    BORDER_FOCUS = Color(0x1f6feb)
    TEXT         = Color(0xe6edf3)
    TEXT_DIM     = Color(0x8b949e)
    TEXT_MUTED   = Color(0x6e7681)
    BLUE         = Color(0x58a6ff)
    GREEN        = Color(0x3fb950)
    ORANGE       = Color(0xd29922)
    RED          = Color(0xf85149)
    PURPLE       = Color(0xbc8cff)
    PINK         = Color(0xff7b72)
    CYAN         = Color(0x39c5cf)

    _FONT_FAM      = "Segoe UI"
    _FONT_MONO     = "Consolas"
    FONT_UI        = Font(_FONT_FAM, Font.PLAIN, 12)
    FONT_UI_BOLD   = Font(_FONT_FAM, Font.BOLD, 12)
    FONT_TITLE     = Font(_FONT_FAM, Font.BOLD, 14)
    FONT_HEADER    = Font(_FONT_FAM, Font.BOLD, 16)
    FONT_SMALL     = Font(_FONT_FAM, Font.PLAIN, 11)
    FONT_MONO      = Font(_FONT_MONO, Font.PLAIN, 11)
    FONT_MONO_BOLD = Font(_FONT_MONO, Font.BOLD, 11)

    @staticmethod
    def apply_root(comp):
        comp.setBackground(Theme.BG_ROOT)
        comp.setForeground(Theme.TEXT)

    @staticmethod
    def apply_surface(comp):
        comp.setBackground(Theme.BG_SURFACE)
        comp.setForeground(Theme.TEXT)

    @staticmethod
    def style_button(btn, variant="default"):
        btn.setFont(Theme.FONT_UI_BOLD)
        btn.setFocusPainted(False)
        btn.setBorderPainted(True)
        btn.setOpaque(True)
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        if variant == "primary":
            bg, fg, border = Theme.BLUE, Color.WHITE, Theme.BLUE
        elif variant == "success":
            bg, fg, border = Theme.GREEN, Color(0x0d1117), Theme.GREEN
        elif variant == "danger":
            bg, fg, border = Theme.RED, Color.WHITE, Theme.RED
        elif variant == "ghost":
            bg, fg, border = Theme.BG_SURFACE, Theme.TEXT_DIM, Theme.BORDER
        else:
            bg, fg, border = Theme.BG_ELEVATED, Theme.TEXT, Theme.BORDER
        btn.setBackground(bg); btn.setForeground(fg)
        btn.setBorder(CompoundBorder(LineBorder(border, 1, True),
                                     EmptyBorder(6, 14, 6, 14)))
        orig_bg = bg
        hover_bg = Theme._blend(bg, Color.WHITE, 0.10)
        class Hover(MouseAdapter):
            def mouseEntered(self, e): btn.setBackground(hover_bg)
            def mouseExited(self, e):  btn.setBackground(orig_bg)
        btn.addMouseListener(Hover())

    @staticmethod
    def _blend(c1, c2, ratio):
        r = int(c1.getRed()   * (1-ratio) + c2.getRed()   * ratio)
        g = int(c1.getGreen() * (1-ratio) + c2.getGreen() * ratio)
        b = int(c1.getBlue()  * (1-ratio) + c2.getBlue()  * ratio)
        return Color(max(0,min(255,r)), max(0,min(255,g)), max(0,min(255,b)))

    @staticmethod
    def style_field(field):
        field.setBackground(Theme.BG_INPUT)
        field.setForeground(Theme.TEXT)
        field.setCaretColor(Theme.BLUE)
        field.setFont(Theme.FONT_UI)
        field.setBorder(CompoundBorder(LineBorder(Theme.BORDER, 1, True),
                                       EmptyBorder(6, 8, 6, 8)))

    @staticmethod
    def style_area(area, mono=False):
        area.setBackground(Theme.BG_SURFACE)
        area.setForeground(Theme.TEXT)
        area.setCaretColor(Theme.BLUE)
        area.setFont(Theme.FONT_MONO if mono else Theme.FONT_UI)
        area.setBorder(EmptyBorder(10, 12, 10, 12))
        try: area.setSelectionColor(Theme.BLUE)
        except Exception: pass
        try: area.setSelectedTextColor(Color.WHITE)
        except Exception: pass

    @staticmethod
    def style_checkbox(cb):
        cb.setBackground(Theme.BG_ROOT)
        cb.setForeground(Theme.TEXT)
        cb.setFont(Theme.FONT_UI)
        cb.setFocusPainted(False)
        cb.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))

    @staticmethod
    def style_label(lbl, variant="default"):
        lbl.setForeground({
            "default": Theme.TEXT, "dim": Theme.TEXT_DIM,
            "muted":   Theme.TEXT_MUTED, "accent": Theme.BLUE,
            "success": Theme.GREEN, "warning": Theme.ORANGE,
            "danger":  Theme.RED,
        }.get(variant, Theme.TEXT))
        lbl.setFont(Theme.FONT_UI)

    @staticmethod
    def style_tabs(tabs):
        tabs.setBackground(Theme.BG_ROOT)
        tabs.setForeground(Theme.TEXT)
        tabs.setFont(Theme.FONT_UI_BOLD)

    @staticmethod
    def style_scrollpane(sp):
        sp.setBackground(Theme.BG_ROOT)
        sp.setBorder(LineBorder(Theme.BORDER, 1, True))
        try: sp.getViewport().setBackground(Theme.BG_SURFACE)
        except Exception: pass

    @staticmethod
    def group_border(title):
        tb = TitledBorder(LineBorder(Theme.BORDER, 1, True),
                          "  " + title + "  ",
                          TitledBorder.LEFT, TitledBorder.TOP,
                          Theme.FONT_TITLE, Theme.BLUE)
        return CompoundBorder(EmptyBorder(6, 6, 6, 6), tb)

    @staticmethod
    def group_panel(title):
        p = JPanel(GridBagLayout())
        p.setBackground(Theme.BG_ROOT)
        p.setBorder(Theme.group_border(title))
        return p


# ============================================================
#  Logger
# ============================================================
class Logger(object):
    def __init__(self, callbacks=None):
        self.stdout = None; self.stderr = None
        if callbacks:
            try:
                self.stdout = java.io.PrintWriter(callbacks.getStdout(), True)
                self.stderr = java.io.PrintWriter(callbacks.getStderr(), True)
            except Exception: pass

    def _p(self, s, m):
        try:
            if s: s.println(m)
            else: print(m)
        except Exception: pass

    def info(self, m):  self._p(self.stdout, "[INFO] " + str(m))
    def debug(self, m): self._p(self.stdout, "[DEBUG] " + str(m))
    def error(self, m, exc=None):
        msg = "[ERROR] " + str(m)
        if exc: msg += ": " + str(exc)
        self._p(self.stderr, msg)
        if exc and self.stderr:
            try: traceback.print_exc(file=self.stderr)
            except Exception: pass


# ============================================================
#  Settings
# ============================================================
class SettingsStore(object):
    def __init__(self, logger=None):
        self.path = os.path.join(os.path.expanduser("~"), ".burpai_config.json")
        self.data = {}; self.logger = logger; self._load()

    def _load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "rb") as f:
                    self.data = json.loads(f.read().decode("utf-8"))
        except Exception as e:
            self.data = {}
            if self.logger: self.logger.error("settings load", e)

    def _save(self):
        try:
            with open(self.path, "wb") as f:
                f.write(json.dumps(self.data, ensure_ascii=False, indent=2).encode("utf-8"))
        except Exception as e:
            if self.logger: self.logger.error("settings save", e)

    def _g(self, k, d): return self.data.get(k, d)
    def _s(self, k, v): self.data[k] = v; self._save()

    def get_api_key(self):
        return self._g("openrouter_api_key", "") or os.environ.get("OPENROUTER_API_KEY", "")
    def set_api_key(self, v):     self._s("openrouter_api_key", v or "")
    def get_model(self):          return self._g("model_name", "openrouter/auto")
    def set_model(self, v):       self._s("model_name", v or "openrouter/auto")

    def get_notebook_path(self):
        return self._g("notebook_path", os.path.join(os.path.expanduser("~"), "burpai_notebook.txt"))
    def set_notebook_path(self, v):
        self._s("notebook_path", v or os.path.join(os.path.expanduser("~"), "burpai_notebook.txt"))

    def get_rpm_limit(self):
        try: return int(self._g("rpm_limit", 30))
        except Exception: return 30
    def set_rpm_limit(self, v):
        try: self._s("rpm_limit", int(v))
        except Exception: self._s("rpm_limit", 30)

    def get_auto_mode(self):    return bool(self._g("auto_mode", True))
    def set_auto_mode(self, v): self._s("auto_mode", bool(v))
    def get_max_iters(self):
        try: return int(self._g("max_iters", 15))
        except Exception: return 15
    def set_max_iters(self, v):
        try: self._s("max_iters", int(v))
        except Exception: self._s("max_iters", 15)

    def get_temperature(self):
        try: return float(self._g("temperature", 0.2))
        except Exception: return 0.2
    def set_temperature(self, v):
        try: self._s("temperature", float(v))
        except Exception: self._s("temperature", 0.2)

    def get_max_tokens(self):
        try: return int(self._g("max_tokens", 4096))
        except Exception: return 4096
    def set_max_tokens(self, v):
        try: self._s("max_tokens", int(v))
        except Exception: self._s("max_tokens", 4096)

    def get_use_native_tools(self):    return bool(self._g("use_native_tools", True))
    def set_use_native_tools(self, v): self._s("use_native_tools", bool(v))
    def get_persist_conversation(self):    return bool(self._g("persist_conversation", True))
    def set_persist_conversation(self, v): self._s("persist_conversation", bool(v))

    def get_system_prompt(self):
        v = self._g("system_prompt", None)
        return v if v else self._default_system_prompt()
    def set_system_prompt(self, v): self._s("system_prompt", v or "")

    def _default_system_prompt(self):
        return (
"You are BurpAI, an evidence-driven security-analysis agent embedded in Burp Suite.\n"
"You help authorized security testers explore targets, analyze HTTP traffic, and\n"
"identify vulnerabilities.\n"
"\n"
"## Environment\n"
"\n"
"You operate inside Burp Suite with tools (provided via the function-calling API\n"
"with full parameter schemas) for:\n"
"- Target site map enumeration: list_target_sitemap, search_target\n"
"- Proxy history search & inspection: search_http, list_http_sitemap,\n"
"  get_http_entry, get_http_body, get_http_body_by_url\n"
"- Actions: propose_request, send_request, append_notebook\n"
"- Termination: final_answer\n"
"\n"
"If your model supports native function calls, use them directly. Otherwise\n"
"return tool invocations as JSON in your response; the extension accepts both.\n"
"\n"
"## Core Rules\n"
"\n"
"**No fabrication.** Never invent URLs, endpoints, parameters, or evidence.\n"
"If you don't know, call a tool. If you still don't know, say \"unknown\".\n"
"\n"
"**Scope discipline.** Respect Burp scope by default (respect_scope=true).\n"
"Pass respect_scope=false only when (a) the user explicitly says so\n"
"(\"ignore scope\", \"everything is in scope\"), or (b) an in-scope search returned\n"
"nothing and you're documenting the broader retry. Note: search_target and\n"
"search_http auto-retry with respect_scope=false on empty results and mark\n"
"broadened_scope=true in the response - check that field.\n"
"\n"
"**Safety by default.** Prefer propose_request (queues for user review) over\n"
"send_request (sends immediately). Use send_request only when the user has\n"
"explicitly authorized live sending of that specific request.\n"
"\n"
"**No intent-guessing.** Do not map user phrases to URL paths. \"Login form\" is\n"
"a concept, not /login-form. When intent is unclear, search or ask.\n"
"\n"
"**Cite evidence.** Every claim needs a URL or history index. Use \"likely\" /\n"
"\"appears to\" when data is thin. Never claim a vulnerability without a\n"
"reproducible request.\n"
"\n"
"## Workflow\n"
"\n"
"**Discovery:** enumerate (list_target_sitemap / list_http_sitemap) -> narrow\n"
"(search_target / search_http) -> inspect (get_http_entry / get_http_body).\n"
"\n"
"**Testing:** find real requests (search_http) -> propose modifications\n"
"(propose_request) with rationale + confidence (0.0-1.0). Do not propose\n"
"payloads against parameters or endpoints you have not verified exist.\n"
"\n"
"**Empty results:** search tools already auto-broaden scope. If they still\n"
"return nothing: try different keywords, then call final_answer explaining\n"
"what you searched.\n"
"\n"
"**Chaining:** prior tool results appear as `tool` role messages. Reference\n"
"them by index (\"history #42\"). Never re-run an identical call - the agent\n"
"loop will block duplicate signatures.\n"
"\n"
"## Stopping\n"
"\n"
"Call `final_answer` when:\n"
"- You have a complete answer with evidence\n"
"- You have a useful partial answer with named gaps\n"
"- Three different approaches have all failed\n"
"\n"
"Do not continue past the user's actual question. Do not stop mid-investigation\n"
"just because one tool succeeded - chain tools when the question requires it.\n"
"\n"
"`final_answer.summary` should include: what you found (with citations), what\n"
"you couldn't verify, and concrete next steps for partial answers.\n"
"\n"
"## Response Style\n"
"\n"
"- Be concise. Brief reasoning, then act.\n"
"- Parallelize independent tool calls in one turn (e.g. two different searches).\n"
"- Serialize dependent calls across turns (search -> get_http_body of a hit).\n"
"- URLs verbatim, never paraphrased.\n"
"- Vulnerability claims require a reproducible propose_request.\n"
"\n"
"## Examples\n"
"\n"
"**Vague question - \"find admin pages\":**\n"
"search_target(query=\"admin\") -> if thin, search_http(query=\"admin\", in_body=true)\n"
"-> final_answer citing endpoints with history indexes.\n"
"\n"
"**Testing - \"check id= for SQLi\":**\n"
"search_http(query=\"id=\", in_req=true) to find real occurrences ->\n"
"propose_request(url=<real endpoint from results>, method=<real method>,\n"
"rationale=\"error-based SQLi probe on <param> from history #N\", confidence=0.6)\n"
"-> final_answer summarizing what was queued.\n"
"\n"
"**Empty - \"find /wp-admin\":**\n"
"search_target(query=\"wp-admin\") -> auto-broadens, still empty ->\n"
"search_http(query=\"wp-admin\", in_req=true) -> still empty ->\n"
"final_answer(\"No wp-admin references in scope or history. Site likely isn't\n"
"WordPress. Suggest checking response headers or robots.txt for actual CMS.\")\n"
        )


# ============================================================
#  HTML chat renderer
# ============================================================
class HtmlRenderer(object):
    CSS = """
    <style>
      body {
        font-family: 'Segoe UI', -apple-system, sans-serif;
        font-size: 13px;
        background: #0d1117;
        color: #e6edf3;
        margin: 0; padding: 14px 16px;
      }
      .msg {
        margin: 10px 0; padding: 10px 14px; border-radius: 10px;
        border-left: 3px solid #30363d;
      }
      .msg .hdr {
        display: block; font-weight: 600; font-size: 11px;
        letter-spacing: 0.6px; text-transform: uppercase; margin-bottom: 6px;
      }
      .msg .time { color: #6e7681; font-weight: 400; font-size: 10px; margin-left: 8px; }
      .msg .body { color: #e6edf3; line-height: 1.55; }
      .msg .body code, .msg .body pre {
        font-family: Consolas, monospace;
        background: #010409; color: #d2a8ff;
        border: 1px solid #30363d; border-radius: 4px;
        padding: 1px 5px; font-size: 12px;
      }
      .msg .body pre {
        padding: 8px 12px; margin: 6px 0;
        white-space: pre-wrap; word-break: break-word;
      }
      .user      { background: #16233b; border-left-color: #58a6ff; }
      .user      .hdr { color: #58a6ff; }
      .assistant { background: #14261a; border-left-color: #3fb950; }
      .assistant .hdr { color: #3fb950; }
      .tool      { background: #2a1f14; border-left-color: #d29922; }
      .tool      .hdr { color: #d29922; }
      .system    { background: #1a1a2a; border-left-color: #bc8cff; }
      .system    .hdr { color: #bc8cff; }
      .error     { background: #2a1414; border-left-color: #f85149; }
      .error     .hdr { color: #f85149; }
    </style>
    """

    ROLE_META = {
        "user":      ("user",      "&#9679; USER"),
        "assistant": ("assistant", "&#9670; ASSISTANT"),
        "tool":      ("tool",      "&#9656; TOOL"),
        "system":    ("system",    "&#9670; SYSTEM"),
        "error":     ("error",     "&#9888; ERROR"),
    }

    def __init__(self):
        self.parts = []

    def _esc(self, s):
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _format_body(self, text):
        if not text: return ""
        out = []; i = 0
        while i < len(text):
            if text[i:i+3] == "```":
                end = text.find("```", i+3)
                if end == -1:
                    out.append("<pre>" + self._esc(text[i+3:]) + "</pre>"); break
                block = text[i+3:end]
                if "\n" in block:
                    first, rest = block.split("\n", 1)
                    if first and " " not in first and len(first) < 20:
                        block = rest
                out.append("<pre>" + self._esc(block) + "</pre>")
                i = end + 3; continue
            if text[i] == "`":
                end = text.find("`", i+1)
                if end != -1 and end - i < 200:
                    out.append("<code>" + self._esc(text[i+1:end]) + "</code>")
                    i = end + 1; continue
            j = i
            while j < len(text) and text[j] != "`": j += 1
            out.append(self._esc(text[i:j]).replace("\n", "<br>"))
            i = j
        return "".join(out)

    def add(self, role, text, timestamp=None):
        cls, label = self.ROLE_META.get(role, ("system", role.upper()))
        ts = timestamp or time.strftime("%H:%M:%S")
        body_html = self._format_body(text)
        self.parts.append(
            "<div class='msg " + cls + "'>"
            "<span class='hdr'>" + label + "<span class='time'>" + ts + "</span></span>"
            "<div class='body'>" + body_html + "</div>"
            "</div>")

    def clear(self):
        self.parts = []

    def to_html(self):
        return ("<html><head>" + self.CSS + "</head><body>"
                + "".join(self.parts) + "</body></html>")


# ============================================================
#  ToolRegistry
# ============================================================
class ToolRegistry(object):
    def __init__(self):
        self._tools = {}

    def register(self, name, description, parameters, handler):
        self._tools[name] = {
            "schema": {"type":"function","function":{
                "name": name, "description": description,
                "parameters": parameters or {"type":"object","properties":{}}}},
            "handler": handler}

    def get_schemas(self):
        return [t["schema"] for t in self._tools.values()]

    def describe_for_prompt(self):
        lines = ["Available tools (call via JSON):"]
        for name, t in self._tools.items():
            desc = t["schema"]["function"]["description"]
            keys = list((t["schema"]["function"]["parameters"].get("properties") or {}).keys())
            lines.append("  - {}({}): {}".format(name, ", ".join(keys), desc))
        return "\n".join(lines)

    def names(self): return list(self._tools.keys())

    def execute(self, name, args):
        if name not in self._tools:
            return {"ok": False, "error": "unknown_tool:" + str(name)}
        try:
            return {"ok": True, "result": self._tools[name]["handler"](args or {})}
        except Exception as e:
            return {"ok": False, "error": str(e), "trace": traceback.format_exc()}


# ============================================================
#  ConversationState
# ============================================================
class ConversationState(object):
    MAX_MESSAGES = 80
    MAX_TOOL_RESULT_CHR = 12000
    MAX_TOTAL_CHR = 260000

    def __init__(self, system_prompt=""):
        self.system_prompt = system_prompt or ""
        self.messages = []
        if system_prompt:
            self.messages.append({"role": "system", "content": system_prompt})

    def add_user(self, content):
        self.messages.append({"role":"user","content": content or ""})
        self._maybe_compact()

    def add_assistant(self, content, tool_calls=None):
        m = {"role":"assistant","content": content or ""}
        if tool_calls: m["tool_calls"] = tool_calls
        self.messages.append(m)
        self._maybe_compact()

    def add_tool_result(self, tool_call_id, name, result):
        if isinstance(result, (dict, list)):
            try:    content = json.dumps(result, ensure_ascii=False, default=str)
            except Exception: content = str(result)
        else:
            content = str(result)
        if len(content) > self.MAX_TOOL_RESULT_CHR:
            content = content[:self.MAX_TOOL_RESULT_CHR] + \
                      "\n...[truncated {} chars]".format(len(content) - self.MAX_TOOL_RESULT_CHR)
        self.messages.append({"role":"tool","tool_call_id":tool_call_id,
                              "name": name, "content": content})
        self._maybe_compact()

    def update_system_prompt(self, prompt):
        self.system_prompt = prompt or ""
        non_sys = [m for m in self.messages if m.get("role") != "system"]
        head = ([{"role":"system","content": self.system_prompt}] if self.system_prompt else [])
        self.messages = head + non_sys

    def clear(self):
        self.messages = []
        if self.system_prompt:
            self.messages.append({"role":"system","content": self.system_prompt})

    def get_messages(self):
        return list(self.messages)

    def _total_chars(self):
        n = 0
        for m in self.messages:
            try:
                n += len(str(m.get("content","")))
                if m.get("tool_calls"): n += len(json.dumps(m["tool_calls"]))
            except Exception: pass
        return n

    def _maybe_compact(self):
        if len(self.messages) <= self.MAX_MESSAGES and self._total_chars() <= self.MAX_TOTAL_CHR:
            return
        sys_m = [m for m in self.messages if m.get("role") == "system"]
        non   = [m for m in self.messages if m.get("role") != "system"]
        keep  = non[-24:] if len(non) > 24 else non
        dropped = len(non) - len(keep)
        ids = set()
        for m in keep:
            if m.get("role") == "assistant":
                for c in (m.get("tool_calls") or []):
                    if c.get("id"): ids.add(c["id"])
        keep = [m for m in keep if m.get("role") != "tool" or m.get("tool_call_id") in ids]
        marker = []
        if dropped > 0:
            marker = [{"role":"system",
                       "content":"[Context compacted: {} earlier messages summarized.]".format(dropped)}]
        self.messages = sys_m + marker + keep


# ============================================================
#  OpenRouter client (with reasoning fallback & truncation warning)
# ============================================================
class OpenRouterClient(object):
    def __init__(self, callbacks, logger=None):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.logger = logger
        self.url = "https://openrouter.ai/api/v1/chat/completions"
        self.models_url = "https://openrouter.ai/api/v1/models"
        self.debug_logger = None

    def set_debug_logger(self, fn): self.debug_logger = fn
    def _log(self, s):
        try:
            if self.debug_logger: self.debug_logger(str(s))
        except Exception: pass

    def _read_all(self, req, body_bytes, connect_timeout=25, total_timeout=180):
        deadline = time.time() + total_timeout
        resp = (urlopen(req, body_bytes, timeout=connect_timeout)
                if body_bytes is not None else urlopen(req, timeout=connect_timeout))
        chunks = []
        try:
            while True:
                rem = deadline - time.time()
                if rem <= 0:
                    try: resp.close()
                    except Exception: pass
                    raise IOError("total read timeout")
                try: resp.fp._sock.settimeout(min(15, rem))
                except Exception: pass
                c = resp.read(8192)
                if not c: break
                chunks.append(c)
        finally:
            try: resp.close()
            except Exception: pass
        return b"".join(chunks)

    def _add_headers(self, req, api_key):
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        req.add_header("Authorization", "Bearer " + api_key)
        ref = os.environ.get("OPENROUTER_HTTP_REFERER")
        ttl = os.environ.get("OPENROUTER_X_TITLE")
        if ref: req.add_header("HTTP-Referer", ref)
        if ttl: req.add_header("X-Title", ttl)

    def list_models(self, api_key):
        if not api_key: return {"ok": False, "content":"missing api key"}
        try:
            req = Request(self.models_url)
            req.add_header("Authorization","Bearer "+api_key)
            req.add_header("Accept","application/json")
            raw = self._read_all(req, None, 20, 60)
            return {"ok": True, "content": raw.decode("utf-8","ignore"), "status": 200}
        except HTTPError as e:
            body = b""
            try: body = e.read()
            except Exception: pass
            return {"ok": False, "content": str(e),
                    "raw": body.decode("utf-8","ignore"),
                    "status": getattr(e,"code",0)}
        except Exception as e:
            return {"ok": False, "content": str(e), "status": 0}

    def chat(self, api_key, model, messages, tools=None, tool_choice="auto",
             temperature=0.2, max_tokens=2048, max_retries=3):
        if not api_key:
            return {"ok": False, "error":"missing_api_key",
                    "content":"", "tool_calls":[], "status":0}
        payload = {"model": model or "openrouter/auto",
                   "messages": messages, "temperature": float(temperature)}
        if max_tokens: payload["max_tokens"] = int(max_tokens)
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice or "auto"
        last = None
        for attempt in range(max_retries):
            if attempt > 0:
                wait = min(30, 2 ** attempt)
                self._log("retry #{} after {}s".format(attempt, wait))
                time.sleep(wait)
            res = self._do_call(api_key, payload); last = res
            code = res.get("status", 0)
            if res.get("ok"): return res
            if code == 429 or (500 <= code < 600) or code == 0: continue
            return res
        return last or {"ok": False, "error":"max_retries",
                        "content":"", "tool_calls":[], "status":0}

    def _do_call(self, api_key, payload):
        dbg = []
        try:
            req = Request(self.url)
            self._add_headers(req, api_key)
            body_bytes = json.dumps(payload).encode("utf-8")
            dbg.append("POST " + self.url)
            dbg.append("model=" + str(payload.get("model")))
            dbg.append("msgs=" + str(len(payload.get("messages", []))))
            if payload.get("tools"): dbg.append("tools=" + str(len(payload["tools"])))
            dbg.append("payload_bytes=" + str(len(body_bytes)))
            self._log("\n".join(dbg))
            raw = self._read_all(req, body_bytes, 25, 180)
            txt = raw.decode("utf-8","ignore")
            self._log("resp head: " + txt[:1200])
            try: data = json.loads(txt)
            except Exception as e:
                return {"ok": False, "status":200, "raw": txt, "content":"",
                        "tool_calls":[], "error":"invalid_json:"+str(e),
                        "debug":"\n".join(dbg)}
            if isinstance(data, dict) and data.get("error"):
                err = data["error"]
                msg = err.get("message") if isinstance(err, dict) else str(err)
                return {"ok": False, "status":400, "raw": txt, "content":"",
                        "tool_calls":[], "error": str(msg), "debug":"\n".join(dbg)}
            choices = (data.get("choices") or []) if isinstance(data, dict) else []
            if not choices:
                return {"ok": False, "status":200, "raw": txt, "content":"",
                        "tool_calls":[], "error":"no_choices","debug":"\n".join(dbg)}
            first = choices[0]
            msg = first.get("message") or {}
            content = msg.get("content") or ""
            reasoning = msg.get("reasoning") or ""
            finish = first.get("finish_reason") or ""

            # Fallback for reasoning models (o1, deepseek-r1, dots-studio) that
            # return content=null and put text in `reasoning`, especially when
            # truncated by max_tokens.
            used_reasoning = False
            if not content and reasoning:
                content = str(reasoning)
                used_reasoning = True
                dbg.append("fallback: using 'reasoning' field as content")

            if finish == "length":
                dbg.append("WARNING: finish_reason=length - increase Max Tokens")

            raw_tc = msg.get("tool_calls") or []
            norm = []
            for tc in raw_tc:
                if not isinstance(tc, dict): continue
                fn = tc.get("function") or {}
                norm.append({
                    "id": tc.get("id") or ("call_" + uuid.uuid4().hex[:12]),
                    "type": tc.get("type","function"),
                    "function": {"name": fn.get("name") or "",
                                 "arguments": fn.get("arguments") or "{}"}})
            return {"ok": True, "status":200, "raw": txt,
                    "content": content, "tool_calls": norm,
                    "finish_reason": finish,
                    "usage": data.get("usage") or {},
                    "used_reasoning": used_reasoning,
                    "debug": "\n".join(dbg)}
        except HTTPError as e:
            body = b""
            try: body = e.read()
            except Exception: pass
            return {"ok": False, "status": getattr(e,"code",0),
                    "raw": body.decode("utf-8","ignore"),
                    "content":"", "tool_calls":[],
                    "error": str(e), "debug":"\n".join(dbg)}
        except URLError as e:
            return {"ok": False, "status":0, "raw":"","content":"","tool_calls":[],
                    "error": str(e), "debug":"\n".join(dbg)}
        except Exception as e:
            return {"ok": False, "status":0, "raw":"","content":"","tool_calls":[],
                    "error": str(e), "debug":"\n".join(dbg + [traceback.format_exc()])}


# ============================================================
#  Burp helpers
# ============================================================
class TargetHelper(object):
    def __init__(self, callbacks, logger=None):
        self.callbacks = callbacks; self.helpers = callbacks.getHelpers(); self.logger = logger

    def list_urls(self, limit=500):
        try: items = self.callbacks.getSiteMap(None)
        except Exception: items = []
        out = []
        for it in items[:limit]:
            try: out.append(str(self.helpers.analyzeRequest(it).getUrl()))
            except Exception: pass
        return out

    def list_urls_filtered(self, path_prefix=None, max_depth=-1, respect_scope=True,
                           limit=500, host_sub=None):
        try: items = self.callbacks.getSiteMap(None)
        except Exception: items = []
        out = []
        base = len([s for s in str(path_prefix or "").split('/') if s])
        for it in items:
            try:
                url = self.helpers.analyzeRequest(it).getUrl()
                if respect_scope and not self.callbacks.isInScope(url): continue
                if host_sub and host_sub.lower() not in (url.getHost() or "").lower(): continue
                p = url.getPath() if hasattr(url,'getPath') else str(url)
                if path_prefix and not p.startswith(path_prefix): continue
                segs = [s for s in p.split('/') if s]
                rel = max(0, len(segs) - base)
                if max_depth >= 0 and rel > max_depth: continue
                out.append(str(url))
                if len(out) >= limit: break
            except Exception: pass
        return out


class HttpHistoryHelper(object):
    def __init__(self, callbacks, logger=None):
        self.callbacks = callbacks; self.helpers = callbacks.getHelpers(); self.logger = logger

    def _normalize_path(self, p):
        if not p: return p
        try:
            out = []
            for seg in p.split('/'):
                if not seg: out.append(seg); continue
                if seg.isdigit() and len(seg) >= 4: out.append('{id}')
                elif len(seg) == 36 and seg.count('-') == 4: out.append('{uuid}')
                elif len(seg) == 24 and all(c in '0123456789abcdefABCDEF' for c in seg):
                    out.append('{objectid}')
                elif len(seg) in (32,40,64) and all(c in '0123456789abcdefABCDEF' for c in seg):
                    out.append('{hash}')
                else: out.append(seg)
            return '/'.join(out)
        except Exception: return p

    def list(self, limit=500):
        try: items = self.callbacks.getProxyHistory()
        except Exception: items = []
        out = []
        for it in items[-limit:]:
            try:
                req = self.helpers.analyzeRequest(it)
                resp = it.getResponse(); status = 0; mime = ""
                if resp:
                    ri = self.helpers.analyzeResponse(resp)
                    status = ri.getStatusCode(); mime = ri.getStatedMimeType()
                out.append({"method": req.getMethod(), "url": str(req.getUrl()),
                            "status": status, "mime": str(mime)})
            except Exception: pass
        return out

    def search(self, query, limit=200, respect_scope=True, in_body=False, in_req=False,
               in_headers=False, regex=False, status_min=0, status_max=999,
               mime_sub="", host_sub=""):
        q = query or ""
        if not regex: q = q.lower()
        if not (in_body or in_req or in_headers): in_body = in_req = in_headers = True
        try: items = self.callbacks.getProxyHistory()
        except Exception: items = []
        patt = None
        if regex:
            try: patt = re.compile(query, re.IGNORECASE)
            except Exception: patt = None
        results = []
        for idx in range(len(items)-1, -1, -1):
            it = items[idx]
            try:
                ri = self.helpers.analyzeRequest(it)
                uo = ri.getUrl(); url = str(uo)
                if respect_scope and not self.callbacks.isInScope(uo): continue
                if host_sub and host_sub.lower() not in (uo.getHost() or "").lower(): continue
                matched = False; snip = ""
                if patt and patt.search(url):
                    matched = True; snip = "URL: " + url
                elif not patt and q in url.lower():
                    matched = True; snip = "URL: " + url
                if not matched and in_req:
                    try:
                        raw = self.helpers.bytesToString(it.getRequest())
                        if patt:
                            m = patt.search(raw)
                            if m:
                                p = m.start(); matched = True
                                snip = "REQ: " + raw[max(0,p-80):p+80].replace("\n"," ")
                        else:
                            if q in raw.lower():
                                p = raw.lower().find(q); matched = True
                                snip = "REQ: " + raw[max(0,p-80):p+80].replace("\n"," ")
                    except Exception: pass
                if not matched and (in_body or in_headers):
                    resp = it.getResponse()
                    if resp:
                        try:
                            if status_min > 0 or status_max < 999 or mime_sub:
                                rri = self.helpers.analyzeResponse(resp)
                                st = rri.getStatusCode(); mt = rri.getStatedMimeType() or ""
                                if st < status_min or st > status_max: continue
                                if mime_sub and mime_sub.lower() not in mt.lower(): continue
                            raw = self.helpers.bytesToString(resp)
                            if patt:
                                m = patt.search(raw)
                                if m:
                                    p = m.start(); matched = True
                                    snip = "RESP: " + raw[max(0,p-80):p+80].replace("\n"," ")
                            else:
                                if q in raw.lower():
                                    p = raw.lower().find(q); matched = True
                                    snip = "RESP: " + raw[max(0,p-80):p+80].replace("\n"," ")
                        except Exception: pass
                if matched:
                    method = ri.getMethod(); status = 0; mime = ""
                    if it.getResponse():
                        try:
                            rri = self.helpers.analyzeResponse(it.getResponse())
                            status = rri.getStatusCode(); mime = rri.getStatedMimeType()
                        except Exception: pass
                    results.append({"index": idx, "url": url, "method": method,
                                    "status": status, "mime": str(mime), "match": snip})
                if len(results) >= limit: break
            except Exception: pass
        return results

    def get_entry(self, index):
        try:
            items = self.callbacks.getProxyHistory()
            if index < 0 or index >= len(items): return None
            it = items[index]
            req = self.helpers.analyzeRequest(it)
            resp = it.getResponse(); status = 0; mime = ""; body = ""
            if resp:
                ri = self.helpers.analyzeResponse(resp)
                status = ri.getStatusCode(); mime = ri.getStatedMimeType()
                body = self.helpers.bytesToString(resp)[ri.getBodyOffset():]
            return {"url": str(req.getUrl()), "method": req.getMethod(),
                    "status": status, "mime": str(mime), "body": body[:2000]}
        except Exception: return None

    def get_body(self, index, offset=0, limit=-1):
        try:
            items = self.callbacks.getProxyHistory()
            if index < 0 or index >= len(items): return None
            resp = items[index].getResponse()
            if not resp: return ""
            ri = self.helpers.analyzeResponse(resp)
            body = self.helpers.bytesToString(resp)[ri.getBodyOffset():]
            off = max(0, int(offset or 0)); lim = int(limit or -1)
            return body[off:] if lim <= 0 else body[off:off+lim]
        except Exception: return None

    def list_sitemap(self, host=None, path_prefix=None, max_depth=-1,
                     respect_scope=True, limit=500):
        try: items = self.callbacks.getProxyHistory()
        except Exception: items = []
        out = []; seen = set()
        base = len([s for s in str(path_prefix or "").split('/') if s])
        for idx in range(len(items)-1, -1, -1):
            it = items[idx]
            try:
                req = self.helpers.analyzeRequest(it); uo = req.getUrl()
                if host and host.lower() not in (uo.getHost() or "").lower(): continue
                if respect_scope and not self.callbacks.isInScope(uo): continue
                p = uo.getPath() if hasattr(uo,'getPath') else str(uo)
                if path_prefix and not p.startswith(path_prefix): continue
                segs = [s for s in p.split('/') if s]
                rel = max(0, len(segs) - base)
                if max_depth >= 0 and rel > max_depth: continue
                norm = self._normalize_path(p)
                key = (req.getMethod() or '') + ' ' + norm
                if key in seen: continue
                seen.add(key)
                rs = it.getResponse(); status = 0; mime = ''
                if rs:
                    try:
                        rinfo = self.helpers.analyzeResponse(rs)
                        status = rinfo.getStatusCode(); mime = rinfo.getStatedMimeType() or ''
                    except Exception: pass
                out.append({"index": idx, "method": req.getMethod(), "url": str(uo),
                            "url_pattern": norm, "status": status, "mime": str(mime),
                            "relative_depth": rel})
                if len(out) >= limit: break
            except Exception: pass
        return out

    def get_body_by_url(self, url, offset=0, limit=-1):
        try: items = self.callbacks.getProxyHistory()
        except Exception: items = []
        for idx in range(len(items)-1, -1, -1):
            try:
                if str(self.helpers.analyzeRequest(items[idx]).getUrl()) == url:
                    return self.get_body(idx, offset=offset, limit=limit)
            except Exception: pass
        return None


class JsonUtils(object):
    def _balanced(self, s, o, c):
        i0 = s.find(o)
        if i0 == -1: return None
        d = 0; ins = False; esc = False
        for i in range(i0, len(s)):
            ch = s[i]
            if ins:
                if esc: esc = False
                elif ch == '\\': esc = True
                elif ch == '"': ins = False
            else:
                if ch == '"': ins = True
                elif ch == o: d += 1
                elif ch == c:
                    d -= 1
                    if d == 0: return s[i0:i+1]
        return None

    def extract_json_any(self, text):
        if not text: return None
        try: s = text if isinstance(text, _string_types) else str(text)
        except Exception: return None
        s = s.strip()
        try: return json.loads(s)
        except Exception: pass
        for oc, cc in (('{','}'),('[',']')):
            seg = self._balanced(s, oc, cc)
            if seg:
                try: return json.loads(seg)
                except Exception: pass
        return None


# ============================================================
#  UI
# ============================================================
class BurpUi(object):
    def __init__(self, extender):
        self.extender = extender
        self.root = JPanel(BorderLayout())
        Theme.apply_root(self.root)
        self.root.setBorder(EmptyBorder(6, 6, 6, 6))
        self.tabs = JTabbedPane()
        Theme.style_tabs(self.tabs)
        self.renderer = HtmlRenderer()

        self.chat_view = None; self.input_field = None
        self.status_dot = None; self.status_label = None
        self.status_model = None; self.status_iter = None
        self.api_key_field = None; self.model_field = None
        self.prompt_area = None; self.notebook_field = None
        self.rpm_field = None; self.temp_field = None
        self.max_iters_field = None; self.max_tokens_field = None
        self.auto_mode_cb = None; self.native_tools_cb = None
        self.persist_cb = None
        self.modelio_area = None; self.tool_results_area = None
        self.debug_area = None
        self.target_area = None; self.target_prefix = None
        self.history_area = None; self.history_query = None
        self.queue_area = None; self.kill_checkbox = None

        self._build_tabs()
        self.root.add(self.tabs, BorderLayout.CENTER)

    def _action(self, fn):
        class A(ActionListener):
            def __init__(self, f): self.f = f
            def actionPerformed(self, e): self.f()
        return A(fn)

    def _hpanel(self):
        p = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        p.setBackground(Theme.BG_ROOT)
        return p

    def _vpanel(self):
        p = JPanel()
        p.setBackground(Theme.BG_ROOT)
        p.setLayout(BoxLayout(p, BoxLayout.Y_AXIS))
        return p

    def _spacer(self, w=6, h=1):
        return Box.createRigidArea(Dimension(w, h))

    def _sep(self):
        s = JSeparator(SwingConstants.HORIZONTAL)
        s.setForeground(Theme.BORDER)
        s.setBackground(Theme.BORDER)
        s.setMaximumSize(Dimension(9999, 1))
        return s

    def _scroll(self, comp):
        sp = JScrollPane(comp)
        Theme.style_scrollpane(sp)
        return sp

    def _build_tabs(self):
        self.tabs.addTab("  Agent  ",        self._build_agent_tab())
        self.tabs.addTab("  Target  ",       self._build_target_tab())
        self.tabs.addTab("  HTTP History  ", self._build_history_tab())
        self.tabs.addTab("  Queue  ",        self._build_queue_tab())
        self.tabs.addTab("  Settings  ",     self._build_settings_tab())
        self.tabs.addTab("  Model I/O  ",    self._build_modelio_tab())
        self.tabs.addTab("  Debug  ",        self._build_debug_tab())
        self.tabs.addTab("  Tool Results  ", self._build_toolresults_tab())

    def _build_status_bar(self):
        bar = JPanel(BorderLayout())
        bar.setBackground(Theme.BG_SURFACE)
        bar.setBorder(CompoundBorder(LineBorder(Theme.BORDER, 1, True),
                                     EmptyBorder(6, 12, 6, 12)))
        left = self._hpanel(); left.setBackground(Theme.BG_SURFACE)
        self.status_dot = JLabel(u"\u25CF")
        self.status_dot.setForeground(Theme.GREEN)
        self.status_dot.setFont(Font(Theme._FONT_FAM, Font.BOLD, 14))
        self.status_label = JLabel("Ready")
        Theme.style_label(self.status_label)
        self.status_label.setFont(Theme.FONT_UI_BOLD)
        left.add(self.status_dot); left.add(JLabel("  "))
        left.add(self.status_label)
        right = self._hpanel(); right.setBackground(Theme.BG_SURFACE)
        self.status_model = JLabel("model: -")
        Theme.style_label(self.status_model, "dim")
        self.status_model.setFont(Theme.FONT_MONO)
        self.status_iter = JLabel("iter: 0/0")
        Theme.style_label(self.status_iter, "dim")
        self.status_iter.setFont(Theme.FONT_MONO)
        sep = JLabel("  |  "); Theme.style_label(sep, "muted")
        right.add(self.status_model); right.add(sep); right.add(self.status_iter)
        bar.add(left, BorderLayout.WEST)
        bar.add(right, BorderLayout.EAST)
        return bar

    def set_status(self, state, model=None, iter_str=None):
        colors = {"ready": Theme.GREEN, "running": Theme.BLUE,
                  "waiting": Theme.ORANGE, "error": Theme.RED,
                  "stopped": Theme.TEXT_DIM}
        labels = {"ready": "Ready", "running": "Running",
                  "waiting": "Waiting for model", "error": "Error",
                  "stopped": "Stopped"}
        c = colors.get(state, Theme.GREEN)
        lb = labels.get(state, state.title())
        def _upd():
            try:
                if self.status_dot:   self.status_dot.setForeground(c)
                if self.status_label: self.status_label.setText(lb)
                if model and self.status_model:   self.status_model.setText("model: " + str(model))
                if iter_str and self.status_iter: self.status_iter.setText("iter: " + iter_str)
            except Exception: pass
        try:
            if SwingUtilities.isEventDispatchThread(): _upd()
            else: SwingUtilities.invokeLater(_upd)
        except Exception: _upd()

    def _build_agent_tab(self):
        panel = JPanel(BorderLayout(0, 8))
        Theme.apply_root(panel)
        panel.setBorder(EmptyBorder(8, 8, 8, 8))
        panel.add(self._build_status_bar(), BorderLayout.NORTH)
        self.chat_view = JEditorPane()
        self.chat_view.setEditable(False)
        self.chat_view.setEditorKit(HTMLEditorKit())
        try: self.chat_view.setContentType("text/html")
        except Exception: pass
        self.chat_view.setBackground(Theme.BG_ROOT)
        self.chat_view.setBorder(EmptyBorder(0, 0, 0, 0))
        self.chat_view.setText(self.renderer.to_html())
        chat_scroll = self._scroll(self.chat_view)

        input_wrap = JPanel(BorderLayout(6, 6))
        input_wrap.setBackground(Theme.BG_ROOT)
        input_wrap.setBorder(EmptyBorder(6, 0, 0, 0))
        self.input_field = JTextField()
        Theme.style_field(self.input_field)
        self.input_field.setFont(Font(Theme._FONT_FAM, Font.PLAIN, 13))
        self.input_field.setPreferredSize(Dimension(600, 36))

        buttons = self._hpanel()
        buttons.setBackground(Theme.BG_ROOT)
        send_btn = JButton("Send")
        stop_btn = JButton("Stop")
        new_btn  = JButton("New Chat")
        save_btn = JButton("Save")
        load_btn = JButton("Load")
        Theme.style_button(send_btn, "primary")
        Theme.style_button(stop_btn, "danger")
        Theme.style_button(new_btn, "ghost")
        Theme.style_button(save_btn, "ghost")
        Theme.style_button(load_btn, "ghost")
        send_btn.addActionListener(self._action(self.extender._send_chat))
        stop_btn.addActionListener(self._action(self.extender._stop_agent))
        new_btn.addActionListener(self._action(self.extender._reset_conversation))
        save_btn.addActionListener(self._action(self.extender._quick_save_chat))
        load_btn.addActionListener(self._action(self.extender._quick_load_chat))
        class EnterSend(ActionListener):
            def __init__(self, f): self.f = f
            def actionPerformed(self, e): self.f()
        self.input_field.addActionListener(EnterSend(self.extender._send_chat))
        buttons.add(send_btn); buttons.add(stop_btn)
        buttons.add(new_btn); buttons.add(save_btn); buttons.add(load_btn)

        input_wrap.add(self.input_field, BorderLayout.CENTER)
        input_wrap.add(buttons, BorderLayout.EAST)
        south = JPanel(BorderLayout(0, 4))
        south.setBackground(Theme.BG_ROOT)
        south.add(self._sep(), BorderLayout.NORTH)
        south.add(input_wrap, BorderLayout.CENTER)
        center = JPanel(BorderLayout(0, 6))
        center.setBackground(Theme.BG_ROOT)
        center.add(chat_scroll, BorderLayout.CENTER)
        center.add(south, BorderLayout.SOUTH)
        panel.add(center, BorderLayout.CENTER)
        return panel

    def _build_target_tab(self):
        panel = JPanel(BorderLayout(0, 8))
        Theme.apply_root(panel); panel.setBorder(EmptyBorder(8, 8, 8, 8))
        top = JPanel(BorderLayout(6, 0)); top.setBackground(Theme.BG_ROOT)
        refresh = JButton("Refresh Site Map"); Theme.style_button(refresh, "primary")
        refresh.addActionListener(self._action(self.extender._refresh_target))
        top.add(refresh, BorderLayout.WEST)
        search = self._hpanel(); search.setBackground(Theme.BG_ROOT)
        lbl = JLabel("Prefix"); Theme.style_label(lbl, "dim")
        self.target_prefix = JTextField(24); Theme.style_field(self.target_prefix)
        sbtn = JButton("Search"); Theme.style_button(sbtn)
        sbtn.addActionListener(self._action(self.extender._search_target))
        search.add(lbl); search.add(self.target_prefix); search.add(sbtn)
        top.add(search, BorderLayout.EAST)
        self.target_area = JTextArea(); self.target_area.setEditable(False)
        Theme.style_area(self.target_area, mono=True)
        panel.add(top, BorderLayout.NORTH)
        panel.add(self._scroll(self.target_area), BorderLayout.CENTER)
        return panel

    def _build_history_tab(self):
        panel = JPanel(BorderLayout(0, 8))
        Theme.apply_root(panel); panel.setBorder(EmptyBorder(8, 8, 8, 8))
        top = self._hpanel(); top.setBackground(Theme.BG_ROOT)
        lbl = JLabel("Query"); Theme.style_label(lbl, "dim")
        self.history_query = JTextField(30); Theme.style_field(self.history_query)
        sbtn = JButton("Search"); Theme.style_button(sbtn, "primary")
        lbtn = JButton("List Recent"); Theme.style_button(lbtn)
        sbtn.addActionListener(self._action(self.extender._search_history))
        lbtn.addActionListener(self._action(self.extender._list_history))
        top.add(lbl); top.add(self.history_query); top.add(sbtn); top.add(lbtn)
        self.history_area = JTextArea(); self.history_area.setEditable(False)
        Theme.style_area(self.history_area, mono=True)
        panel.add(top, BorderLayout.NORTH)
        panel.add(self._scroll(self.history_area), BorderLayout.CENTER)
        return panel

    def _build_queue_tab(self):
        panel = JPanel(BorderLayout(0, 8))
        Theme.apply_root(panel); panel.setBorder(EmptyBorder(8, 8, 8, 8))
        bar = self._hpanel(); bar.setBackground(Theme.BG_ROOT)
        ap = JButton("Approve Next"); Theme.style_button(ap, "success")
        rj = JButton("Reject Next");  Theme.style_button(rj, "danger")
        sn = JButton("Send Next");    Theme.style_button(sn, "primary")
        ap.addActionListener(self._action(self.extender._approve_next))
        rj.addActionListener(self._action(self.extender._reject_next))
        sn.addActionListener(self._action(self.extender._send_next))
        self.kill_checkbox = JCheckBox("Kill Switch")
        Theme.style_checkbox(self.kill_checkbox)
        self.kill_checkbox.setForeground(Theme.RED)
        def _kill(): self.extender.kill_switch = self.kill_checkbox.isSelected()
        self.kill_checkbox.addActionListener(self._action(_kill))
        bar.add(ap); bar.add(rj); bar.add(sn)
        bar.add(Box.createHorizontalStrut(24)); bar.add(self.kill_checkbox)
        self.queue_area = JTextArea(); self.queue_area.setEditable(False)
        Theme.style_area(self.queue_area, mono=True)
        panel.add(bar, BorderLayout.NORTH)
        panel.add(self._scroll(self.queue_area), BorderLayout.CENTER)
        return panel

    def _build_modelio_tab(self):
        panel = JPanel(BorderLayout())
        Theme.apply_root(panel); panel.setBorder(EmptyBorder(8, 8, 8, 8))
        self.modelio_area = JTextArea(); self.modelio_area.setEditable(False)
        Theme.style_area(self.modelio_area, mono=True)
        panel.add(self._scroll(self.modelio_area), BorderLayout.CENTER)
        return panel

    def _build_debug_tab(self):
        panel = JPanel(BorderLayout(0, 6))
        Theme.apply_root(panel); panel.setBorder(EmptyBorder(8, 8, 8, 8))
        self.debug_area = JTextArea(); self.debug_area.setEditable(False)
        Theme.style_area(self.debug_area, mono=True)
        bar = self._hpanel(); bar.setBackground(Theme.BG_ROOT)
        cb = JButton("Clear Debug"); Theme.style_button(cb, "ghost")
        cb.addActionListener(self._action(self.extender._clear_debug))
        bar.add(cb)
        panel.add(self._scroll(self.debug_area), BorderLayout.CENTER)
        panel.add(bar, BorderLayout.SOUTH)
        return panel

    def _build_toolresults_tab(self):
        panel = JPanel(BorderLayout(0, 6))
        Theme.apply_root(panel); panel.setBorder(EmptyBorder(8, 8, 8, 8))
        self.tool_results_area = JTextArea(); self.tool_results_area.setEditable(False)
        Theme.style_area(self.tool_results_area, mono=True)
        bar = self._hpanel(); bar.setBackground(Theme.BG_ROOT)
        cb = JButton("Clear"); Theme.style_button(cb, "ghost")
        def _cl():
            self.extender.tool_results = []
            self.tool_results_area.setText("")
        cb.addActionListener(self._action(_cl))
        bar.add(cb)
        panel.add(self._scroll(self.tool_results_area), BorderLayout.CENTER)
        panel.add(bar, BorderLayout.SOUTH)
        return panel

    def _build_settings_tab(self):
        outer = JPanel(BorderLayout())
        Theme.apply_root(outer)
        content = self._vpanel()
        content.setBorder(EmptyBorder(10, 10, 10, 10))

        # ---- Connection group ----
        conn = Theme.group_panel("Connection")
        gbc = self._new_gbc()
        self.api_key_field = JTextField(self.extender.store.get_api_key())
        Theme.style_field(self.api_key_field)
        self._add_setting_row(conn, gbc, 0, "API Key", self.api_key_field, self._save_api_key)
        self.model_field = JTextField(self.extender.store.get_model())
        Theme.style_field(self.model_field)
        self._add_setting_row(conn, gbc, 1, "Model", self.model_field, self._save_model)
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 3; gbc.weightx = 1.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(8, 8, 4, 8)
        btn_row = self._hpanel()
        test_btn = JButton("Test Connection"); Theme.style_button(test_btn, "primary")
        list_btn = JButton("List Models");     Theme.style_button(list_btn)
        test_btn.addActionListener(self._action(self.extender._test_openrouter))
        list_btn.addActionListener(self._action(self.extender._list_models))
        btn_row.add(test_btn); btn_row.add(list_btn)
        conn.add(btn_row, gbc)
        gbc.gridwidth = 1

        # ---- Model Behavior ----
        beh = Theme.group_panel("Model Behavior")
        gbc = self._new_gbc()
        self.temp_field = JTextField(str(self.extender.store.get_temperature()))
        Theme.style_field(self.temp_field)
        self._add_setting_row(beh, gbc, 0, "Temperature", self.temp_field, self._save_temp)
        self.max_tokens_field = JTextField(str(self.extender.store.get_max_tokens()))
        Theme.style_field(self.max_tokens_field)
        self._add_setting_row(beh, gbc, 1, "Max Tokens", self.max_tokens_field, self._save_mt)
        self.max_iters_field = JTextField(str(self.extender.store.get_max_iters()))
        Theme.style_field(self.max_iters_field)
        self._add_setting_row(beh, gbc, 2, "Max Iterations", self.max_iters_field, self._save_mi)

        # ---- Agent Behavior ----
        ag = Theme.group_panel("Agent Behavior")
        gbc = self._new_gbc()
        self.auto_mode_cb = JCheckBox("Autonomous mode (multi-turn tool loop)",
                                      self.extender.store.get_auto_mode())
        Theme.style_checkbox(self.auto_mode_cb)
        self.native_tools_cb = JCheckBox("Use native OpenAI tool calling",
                                         self.extender.store.get_use_native_tools())
        Theme.style_checkbox(self.native_tools_cb)
        self.persist_cb = JCheckBox("Persist conversation across Send",
                                    self.extender.store.get_persist_conversation())
        Theme.style_checkbox(self.persist_cb)
        auto_btn = JButton("Save"); Theme.style_button(auto_btn)
        nt_btn   = JButton("Save"); Theme.style_button(nt_btn)
        pc_btn   = JButton("Save"); Theme.style_button(pc_btn)
        auto_btn.addActionListener(self._action(lambda:
            (self.extender.store.set_auto_mode(self.auto_mode_cb.isSelected()),
             self._toast("Saved"))))
        nt_btn.addActionListener(self._action(lambda:
            (self.extender.store.set_use_native_tools(self.native_tools_cb.isSelected()),
             self._toast("Saved"))))
        pc_btn.addActionListener(self._action(lambda:
            (self.extender.store.set_persist_conversation(self.persist_cb.isSelected()),
             self._toast("Saved"))))
        self._add_cb_row(ag, gbc, 0, self.auto_mode_cb, auto_btn)
        self._add_cb_row(ag, gbc, 1, self.native_tools_cb, nt_btn)
        self._add_cb_row(ag, gbc, 2, self.persist_cb, pc_btn)

        # ---- System Prompt ----
        sp = Theme.group_panel("System Prompt")
        gbc = self._new_gbc()
        self.prompt_area = JTextArea(self.extender.store.get_system_prompt(), 8, 60)
        Theme.style_area(self.prompt_area)
        pa_scroll = self._scroll(self.prompt_area)
        pa_scroll.setPreferredSize(Dimension(500, 200))
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 3
        gbc.weightx = 1.0; gbc.fill = GridBagConstraints.BOTH; gbc.weighty = 1.0
        gbc.insets = Insets(4, 8, 4, 8)
        sp.add(pa_scroll, gbc)
        gbc.gridy = 1; gbc.weighty = 0; gbc.fill = GridBagConstraints.HORIZONTAL
        btn_row2 = self._hpanel()
        sp_save = JButton("Save Prompt");   Theme.style_button(sp_save, "primary")
        sp_rst  = JButton("Reset Default"); Theme.style_button(sp_rst, "ghost")
        sp_save.addActionListener(self._action(self._save_prompt))
        sp_rst.addActionListener(self._action(self._reset_prompt))
        btn_row2.add(sp_save); btn_row2.add(sp_rst)
        sp.add(btn_row2, gbc)
        gbc.gridwidth = 1

        # ---- Storage ----
        st = Theme.group_panel("Storage & Limits")
        gbc = self._new_gbc()
        self.notebook_field = JTextField(self.extender.store.get_notebook_path())
        Theme.style_field(self.notebook_field)
        self._add_setting_row(st, gbc, 0, "Notebook Path", self.notebook_field, self._save_nb)
        self.rpm_field = JTextField(str(self.extender.store.get_rpm_limit()))
        Theme.style_field(self.rpm_field)
        self._add_setting_row(st, gbc, 1, "Rate Limit (RPM)", self.rpm_field, self._save_rpm)

        for g in (conn, beh, ag, sp, st):
            content.add(g)
            content.add(self._spacer(0, 8))

        wrap = self._scroll(content)
        outer.add(wrap, BorderLayout.CENTER)
        return outer

    def _new_gbc(self):
        gbc = GridBagConstraints()
        gbc.insets = Insets(4, 8, 4, 8)
        gbc.fill = GridBagConstraints.HORIZONTAL
        return gbc

    def _add_setting_row(self, panel, gbc, row, label, field, save_fn):
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0
        lbl = JLabel(label); Theme.style_label(lbl, "dim")
        lbl.setPreferredSize(Dimension(140, 24))
        panel.add(lbl, gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        panel.add(field, gbc)
        gbc.gridx = 2; gbc.weightx = 0
        btn = JButton("Save"); Theme.style_button(btn)
        btn.addActionListener(self._action(save_fn))
        panel.add(btn, gbc)

    def _add_cb_row(self, panel, gbc, row, cb, save_btn):
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2; gbc.weightx = 1.0
        panel.add(cb, gbc)
        gbc.gridx = 2; gbc.gridwidth = 1; gbc.weightx = 0
        panel.add(save_btn, gbc)

    def _toast(self, msg):
        JOptionPane.showMessageDialog(self.root, msg)

    def _save_api_key(self):
        self.extender.store.set_api_key(self.api_key_field.getText()); self._toast("Saved")
    def _save_model(self):
        self.extender.store.set_model(self.model_field.getText())
        self.set_status("ready", model=self.model_field.getText())
        self._toast("Saved")
    def _save_prompt(self):
        self.extender.store.set_system_prompt(self.prompt_area.getText())
        self.extender.conversation.update_system_prompt(self.prompt_area.getText())
        self._toast("Saved")
    def _reset_prompt(self):
        d = self.extender.store._default_system_prompt()
        self.prompt_area.setText(d)
        self.extender.store.set_system_prompt(d)
        self.extender.conversation.update_system_prompt(d)
    def _save_nb(self):
        self.extender.store.set_notebook_path(self.notebook_field.getText()); self._toast("Saved")
    def _save_rpm(self):
        self.extender.store.set_rpm_limit(self.rpm_field.getText()); self._toast("Saved")
    def _save_temp(self):
        self.extender.store.set_temperature(self.temp_field.getText()); self._toast("Saved")
    def _save_mt(self):
        self.extender.store.set_max_tokens(self.max_tokens_field.getText()); self._toast("Saved")
    def _save_mi(self):
        self.extender.store.set_max_iters(self.max_iters_field.getText()); self._toast("Saved")


# ============================================================
#  Extender
# ============================================================
class BurpExtender(IBurpExtender, ITab, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp AI Agent")

        self.logger = Logger(callbacks)
        self.store = SettingsStore(self.logger)
        self.client = OpenRouterClient(callbacks, self.logger)
        self.target = TargetHelper(callbacks, self.logger)
        self.history = HttpHistoryHelper(callbacks, self.logger)
        self.json = JsonUtils()

        self.tool_registry = ToolRegistry()
        self.conversation = ConversationState(self.store.get_system_prompt())
        self._register_tools()

        self.queue = []
        self.kill_switch = False
        self.stop_agent_flag = False
        self.send_times = []
        self.tool_results = []
        self.agent_lock = threading.Lock()
        self.agent_running = False

        self.ui = BurpUi(self)
        try: self.client.set_debug_logger(self._log_debug)
        except Exception: pass
        self.ui.set_status("ready", model=self.store.get_model(), iter_str="0/0")
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        self._log_debug("BurpAI Agent ready. Tools: " + ", ".join(self.tool_registry.names()))

    def getTabCaption(self): return "AI Agent"
    def getUiComponent(self): return self.ui.root
    def processHttpMessage(self, toolFlag, isReq, msg): return

    # ---------- Tool registration ----------
    def _register_tools(self):
        R = self.tool_registry
        R.register("list_target_sitemap",
            "List URLs from the Burp Target site map. Supports scope, prefix, depth, host filters.",
            {"type":"object","properties":{
                "path_prefix":{"type":"string"},
                "max_depth":{"type":"integer"},
                "respect_scope":{"type":"boolean"},
                "host_sub":{"type":"string"},
                "limit":{"type":"integer"}}},
            self._tool_list_target_sitemap)
        R.register("search_target",
            "Substring search over URLs in the Target site map. Auto-broadens scope on empty result.",
            {"type":"object","properties":{
                "query":{"type":"string"},
                "path_prefix":{"type":"string"},
                "max_depth":{"type":"integer"},
                "respect_scope":{"type":"boolean"},
                "host_sub":{"type":"string"},
                "limit":{"type":"integer"}},"required":["query"]},
            self._tool_search_target)
        R.register("search_http",
            "Search Burp Proxy history. Matches URLs, request and response by default.",
            {"type":"object","properties":{
                "query":{"type":"string"},
                "regex":{"type":"boolean"},
                "in_body":{"type":"boolean"},
                "in_req":{"type":"boolean"},
                "in_headers":{"type":"boolean"},
                "respect_scope":{"type":"boolean"},
                "status_min":{"type":"integer"},
                "status_max":{"type":"integer"},
                "mime_sub":{"type":"string"},
                "host_sub":{"type":"string"},
                "limit":{"type":"integer"}},"required":["query"]},
            self._tool_search_http)
        R.register("list_http_sitemap",
            "Deduplicated HTTP history endpoints (normalized IDs/UUIDs) with method+path.",
            {"type":"object","properties":{
                "base_url":{"type":"string"},"host":{"type":"string"},
                "path_prefix":{"type":"string"},"max_depth":{"type":"integer"},
                "respect_scope":{"type":"boolean"},"limit":{"type":"integer"}}},
            self._tool_list_http_sitemap)
        R.register("get_http_entry",
            "Fetch one Proxy history entry by index (method, url, status, mime, body preview).",
            {"type":"object","properties":{"index":{"type":"integer"}},"required":["index"]},
            self._tool_get_http_entry)
        R.register("get_http_body",
            "Fetch full response body by history index. Supports offset/limit.",
            {"type":"object","properties":{
                "index":{"type":"integer"},"offset":{"type":"integer"},"limit":{"type":"integer"}
            },"required":["index"]},
            self._tool_get_http_body)
        R.register("get_http_body_by_url",
            "Fetch response body(ies) for URL(s) from history.",
            {"type":"object","properties":{
                "url":{"type":"string"},
                "urls":{"type":"array","items":{"type":"string"}},
                "offset":{"type":"integer"},"limit":{"type":"integer"}}},
            self._tool_get_http_body_by_url)
        R.register("propose_request",
            "Queue an HTTP request for human review before sending. Preferred over send_request.",
            {"type":"object","properties":{
                "method":{"type":"string"},"url":{"type":"string"},
                "headers":{"type":"object"},"body":{"type":"string"},
                "rationale":{"type":"string"},"confidence":{"type":"number"}
            },"required":["method","url"]},
            self._tool_propose_request)
        R.register("send_request",
            "Send an HTTP request immediately (subject to kill switch and RPM limit).",
            {"type":"object","properties":{
                "method":{"type":"string"},"url":{"type":"string"},
                "headers":{"type":"object"},"body":{"type":"string"}
            },"required":["method","url"]},
            self._tool_send_request)
        R.register("append_notebook",
            "Append a note to the notebook file.",
            {"type":"object","properties":{"text":{"type":"string"}},"required":["text"]},
            self._tool_append_notebook)
        R.register("final_answer",
            "Call ONLY when you have a complete answer for the user. Ends the agent loop.",
            {"type":"object","properties":{"summary":{"type":"string"}},"required":["summary"]},
            self._tool_final_answer)

    # ---------- Tool handlers ----------
    def _tool_list_target_sitemap(self, args):
        urls = self.target.list_urls_filtered(
            path_prefix=args.get("path_prefix") or None,
            max_depth=int(args.get("max_depth", -1)),
            respect_scope=bool(args.get("respect_scope", True)),
            host_sub=args.get("host_sub") or None,
            limit=int(args.get("limit", 200)))
        return {"count": len(urls), "urls": urls[:50]}

    def _tool_search_target(self, args):
        q = (args.get("query") or "").lower()
        pref = args.get("path_prefix") or None
        md = int(args.get("max_depth", -1))
        rs = bool(args.get("respect_scope", True))
        lim = int(args.get("limit", 200))
        hsub = args.get("host_sub") or None
        urls = self.target.list_urls_filtered(path_prefix=pref, max_depth=md,
                                              respect_scope=rs, limit=lim, host_sub=hsub)
        hits = [u for u in urls if q in u.lower()][:lim]
        broadened = False
        if not hits and rs:
            u2 = self.target.list_urls_filtered(path_prefix=pref, max_depth=md,
                                                respect_scope=False, limit=lim, host_sub=hsub)
            hits = [u for u in u2 if q in u.lower()][:lim]
            broadened = True
        return {"count": len(hits), "urls": hits[:50], "broadened_scope": broadened}

    def _tool_search_http(self, args):
        items = self.history.search(
            query=args.get("query"),
            limit=int(args.get("limit", 200)),
            respect_scope=bool(args.get("respect_scope", True)),
            in_body=bool(args.get("in_body", False)),
            in_req=bool(args.get("in_req", False)),
            in_headers=bool(args.get("in_headers", False)),
            regex=bool(args.get("regex", False)),
            status_min=int(args.get("status_min", 0)),
            status_max=int(args.get("status_max", 999)),
            mime_sub=str(args.get("mime_sub","")),
            host_sub=str(args.get("host_sub","")))
        broadened = False
        if not items and args.get("respect_scope", True):
            items = self.history.search(
                query=args.get("query"), limit=int(args.get("limit", 200)),
                respect_scope=False,
                in_body=bool(args.get("in_body", False)),
                in_req=bool(args.get("in_req", False)),
                in_headers=bool(args.get("in_headers", False)),
                regex=bool(args.get("regex", False)))
            broadened = True
        return {"count": len(items), "items": items[:50], "broadened_scope": broadened}

    def _tool_list_http_sitemap(self, args):
        base = args.get("base_url"); host = args.get("host"); pref = args.get("path_prefix")
        if base:
            try:
                u = URL(base)
                host = host or (u.getHost() or None)
                pref = pref or (u.getPath() or None)
            except Exception: pass
        items = self.history.list_sitemap(
            host=host, path_prefix=pref,
            max_depth=int(args.get("max_depth", -1)),
            respect_scope=bool(args.get("respect_scope", True)),
            limit=int(args.get("limit", 200)))
        return {"count": len(items), "items": items[:50]}

    def _tool_get_http_entry(self, args):
        idx = int(args.get("index", -1))
        info = self.history.get_entry(idx)
        return {"error":"not_found","index":idx} if not info else {"index":idx,"entry":info}

    def _tool_get_http_body(self, args):
        idx = int(args.get("index", -1))
        off = int(args.get("offset", 0)); lim = int(args.get("limit", -1))
        body = self.history.get_body(idx, offset=off, limit=lim)
        if body is None: return {"error":"not_found","index":idx}
        return {"index": idx, "offset": off, "limit": lim, "length": len(body),
                "body": body[:8000] + ("...[truncated]" if len(body) > 8000 else "")}

    def _tool_get_http_body_by_url(self, args):
        urls = args.get("urls") or ([args.get("url")] if args.get("url") else [])
        out = []
        for u in urls:
            b = self.history.get_body_by_url(str(u),
                offset=int(args.get("offset", 0)), limit=int(args.get("limit", -1)))
            if b is not None:
                out.append({"url": str(u), "length": len(b),
                            "body": b[:6000] + ("...[truncated]" if len(b) > 6000 else "")})
        return {"count": len(out), "items": out}

    def _tool_propose_request(self, args):
        req = {"method":args.get("method","GET"), "url":args.get("url",""),
               "headers":args.get("headers") or {}, "body":args.get("body") or "",
               "rationale":args.get("rationale") or "",
               "confidence":args.get("confidence"), "approved": False}
        self.queue.append(req)
        self._safe_ui(self._refresh_queue_view)
        return {"queued":True,"position":len(self.queue)-1,
                "method":req["method"],"url":req["url"]}

    def _tool_send_request(self, args):
        if self.kill_switch: return {"error":"kill_switch_active"}
        req = {"method":args.get("method","GET"),"url":args.get("url",""),
               "headers":args.get("headers") or {}, "body":args.get("body") or "",
               "approved":True}
        return self._dispatch_request(req)

    def _tool_append_notebook(self, args):
        text = args.get("text","")
        try:
            path = self.store.get_notebook_path()
            with open(path, "ab") as f:
                f.write(("[" + time.strftime("%Y-%m-%d %H:%M:%S") + "] " + text + "\n").encode("utf-8"))
            return {"ok":True,"path":path,"bytes_written":len(text)}
        except Exception as e:
            return {"ok":False,"error":str(e)}

    def _tool_final_answer(self, args):
        return {"final":True,"summary":args.get("summary","")}

    # ---------- Prose JSON parser (fallback for models that ignore native tools) ----------
    def _parse_prose_response(self, content):
        """
        Extract tool_calls / display text / continue flag from prose-JSON response.
        Handles system prompts that force JSON output.

        Accepts either tool-call shape:
          {"tool":"name","args":{...}}
          {"name":"name","arguments":{...}}

        Returns (tool_calls_list, display_text, continue_flag).
        """
        if not content:
            return None, None, None
        parsed = self.json.extract_json_any(content)
        if not isinstance(parsed, dict):
            return None, None, None

        tool_calls = []
        raw_calls = parsed.get("tool_calls") or []
        if isinstance(raw_calls, list):
            for c in raw_calls:
                if not isinstance(c, dict): continue
                name = c.get("name") or c.get("tool")
                if not name: continue
                args = c.get("arguments") or c.get("args") or {}
                if isinstance(args, _string_types):
                    args_str = args
                else:
                    try: args_str = json.dumps(args)
                    except Exception: args_str = "{}"
                tool_calls.append({
                    "id": "call_" + uuid.uuid4().hex[:10],
                    "type": "function",
                    "function": {"name": name, "arguments": args_str}
                })

        display = parsed.get("reply") or parsed.get("thinking") or ""
        cont = parsed.get("continue")
        if cont is None:
            cont = parsed.get("next")

        return (tool_calls if tool_calls else None,
                display if display else None,
                cont)

    # ---------- Chat orchestration ----------
    def _send_chat(self):
        user_text = self.ui.input_field.getText()
        if not user_text or not user_text.strip(): return
        self.ui.input_field.setText("")
        self._append_chat("user", user_text)
        self.stop_agent_flag = False

        with self.agent_lock:
            if self.agent_running:
                self._append_chat("system", "Agent already running - press Stop to interrupt.")
                return
            self.agent_running = True

        if not self.store.get_persist_conversation():
            self.conversation.clear()
        self.conversation.add_user(user_text)
        self.ui.set_status("running", model=self.store.get_model())

        def _bg():
            try: self._run_agent_loop()
            except Exception as e:
                self._log_debug("agent loop crash: " + str(e))
                self._log_debug(traceback.format_exc())
                self._safe_ui(lambda: self._append_chat("error", "Agent crashed: " + str(e)))
                self.ui.set_status("error")
            finally:
                with self.agent_lock: self.agent_running = False
                self.ui.set_status("ready")
        threading.Thread(target=_bg).start()

    def _stop_agent(self):
        self.stop_agent_flag = True
        self._append_chat("system", "Stop requested. Will halt after current step.")
        self.ui.set_status("stopped")

    def _reset_conversation(self):
        self.conversation.clear()
        self.tool_results = []
        self.ui.renderer.clear()
        try: self.ui.chat_view.setText(self.ui.renderer.to_html())
        except Exception: pass
        try: self.ui.tool_results_area.setText("")
        except Exception: pass
        self._append_chat("system", "New conversation started.")
        self.ui.set_status("ready", iter_str="0/0")

    # ---------- Core ReAct loop ----------
    def _run_agent_loop(self):
        api_key = self.store.get_api_key()
        model = self.store.get_model()
        temperature = self.store.get_temperature()
        max_tokens = self.store.get_max_tokens()
        use_native = self.store.get_use_native_tools()
        max_iters = self.store.get_max_iters()
        auto_mode = self.store.get_auto_mode()
        if not auto_mode: max_iters = 1

        cur_sys = self.store.get_system_prompt()
        if not use_native:
            cur_sys = (cur_sys + "\n\n" + self.tool_registry.describe_for_prompt() +
                       "\n\nTo call a tool, return JSON:\n"
                       '  {"tool_calls":[{"name":"<tool>","arguments":{...}}]}\n'
                       "To give the final answer, return JSON:\n"
                       '  {"reply":"<your final answer>"}\n')
        self.conversation.update_system_prompt(cur_sys)

        tools_schema = self.tool_registry.get_schemas() if use_native else None
        signature_seen = {}

        for iteration in range(max_iters):
            if self.stop_agent_flag:
                self._append_chat("system", "Stopped by user."); return

            self.ui.set_status("waiting", model=model,
                               iter_str="{}/{}".format(iteration+1, max_iters))
            self._log_debug("=" * 60)
            self._log_debug("iter {}/{}  msgs={}".format(
                iteration+1, max_iters, len(self.conversation.get_messages())))

            res = self.client.chat(api_key=api_key, model=model,
                                   messages=self.conversation.get_messages(),
                                   tools=tools_schema, tool_choice="auto",
                                   temperature=temperature, max_tokens=max_tokens)

            self.ui.set_status("running", model=model,
                               iter_str="{}/{}".format(iteration+1, max_iters))

            def _dbg():
                try:
                    self.ui.modelio_area.setText(
                        (res.get("debug","") or "") + "\n\n" + (res.get("raw","") or ""))
                except Exception: pass
            self._safe_ui(_dbg)

            if not res.get("ok"):
                err = res.get("error") or res.get("content") or "unknown"
                self._log_debug("model error: " + str(err))
                self._safe_ui(lambda: self._append_chat("error", "Model error: " + str(err)))
                self.ui.set_status("error"); return

            content = res.get("content") or ""
            tool_calls = res.get("tool_calls") or []
            finish = res.get("finish_reason") or ""

            # ---- Always try prose-JSON fallback if native tool_calls empty ----
            # (Some models return tool calls in prose even when tools schema is sent)
            prose_continue = None
            if not tool_calls:
                parsed_calls, parsed_display, parsed_continue = \
                    self._parse_prose_response(content)
                if parsed_calls:
                    tool_calls = parsed_calls
                    self._log_debug("prose-JSON fallback: extracted {} tool call(s)"
                                    .format(len(tool_calls)))
                if parsed_display:
                    content = parsed_display
                prose_continue = parsed_continue

            # ---- Warn on empty response ----
            if not content and not tool_calls:
                warn = "Model returned empty response."
                if finish == "length":
                    warn += (" Reason: hit max_tokens ({}). Increase Max Tokens in "
                             "Settings (reasoning models need 4000+).".format(max_tokens))
                elif res.get("used_reasoning"):
                    warn += " Model uses 'reasoning' field but had no output tokens."
                else:
                    warn += " finish_reason={}".format(finish or "unknown")
                self._log_debug("empty response: " + warn)
                self._safe_ui(lambda w=warn: self._append_chat("error", w))
                self.ui.set_status("error"); return

            # ---- Display + record assistant turn ----
            if content:
                self._safe_ui(lambda c=content: self._append_chat("assistant", c))
            self.conversation.add_assistant(content, tool_calls if tool_calls else None)

            # ---- Termination: no tool_calls -> final answer ----
            if not tool_calls:
                self._log_debug("no tool_calls -> final")
                self.ui.set_status("ready"); return

            # ---- Execute tool calls ----
            saw_final = False
            for tc in tool_calls:
                if self.stop_agent_flag:
                    self._append_chat("system", "Stopped by user."); return
                fn = (tc.get("function") or {})
                name = fn.get("name") or ""
                arg_str = fn.get("arguments") or "{}"
                try:
                    args = (json.loads(arg_str)
                            if isinstance(arg_str, _string_types) else (arg_str or {}))
                    if not isinstance(args, dict): args = {}
                except Exception:
                    args = {}

                sig = self._call_signature(name, args)
                signature_seen[sig] = signature_seen.get(sig, 0) + 1
                if signature_seen[sig] > 2:
                    err_msg = ("You have called '{}' with identical arguments {} times. "
                               "Try different arguments, broaden the query, or produce "
                               "a final answer.".format(name, signature_seen[sig]))
                    self._log_debug("dedup block: " + sig[:200])
                    self.conversation.add_tool_result(tc.get("id"), name, {"error": err_msg})
                    continue

                self._log_debug("exec: {}({})".format(name, arg_str[:200]))
                self._safe_ui(lambda n=name, a=args:
                              self._append_chat("tool",
                                  u"\u2192 " + n + "(" + json.dumps(a)[:200] + ")"))

                out = self.tool_registry.execute(name, args)
                self._record_tool_display(name, args, out)

                if out.get("ok"):
                    payload = out.get("result")
                    self.conversation.add_tool_result(tc.get("id"), name, payload)
                    if name == "final_answer":
                        if isinstance(payload, dict) and payload.get("summary"):
                            self._safe_ui(lambda s=payload["summary"]:
                                          self._append_chat("assistant", s))
                        saw_final = True
                else:
                    err = {"error": out.get("error","unknown"),
                           "hint": "Adjust arguments and try again, "
                                   "or produce a final answer."}
                    self.conversation.add_tool_result(tc.get("id"), name, err)

            if saw_final:
                self.ui.set_status("ready"); return

            # ---- Respect explicit `continue: false` from prose JSON ----
            if prose_continue is False:
                self._log_debug("prose 'continue: false' - stopping after tool execution")
                self.ui.set_status("ready"); return

        self._safe_ui(lambda: self._append_chat("system",
            "Reached max iterations ({}). Ask for a final summary or raise the cap."
            .format(max_iters)))
        self.ui.set_status("ready")

    def _call_signature(self, name, args):
        try: return name + "|" + json.dumps(args, sort_keys=True)
        except Exception: return name + "|" + str(args)

    def _record_tool_display(self, name, args, out):
        try:
            entry = {"tool": name, "ts": time.strftime("%H:%M:%S"),
                     "args": args, "result": out}
            self.tool_results.append(entry)
            if len(self.tool_results) > 100:
                self.tool_results = self.tool_results[-100:]
            def _upd():
                try:
                    txt = "\n\n".join([json.dumps(x, indent=2, default=str)
                                       for x in self.tool_results[-12:]])
                    self.ui.tool_results_area.setText(txt)
                    self.ui.tool_results_area.setCaretPosition(
                        self.ui.tool_results_area.getDocument().getLength())
                except Exception: pass
            self._safe_ui(_upd)
        except Exception: pass

    # ---------- HTTP dispatch ----------
    def _dispatch_request(self, item):
        try:
            now = time.time()
            self.send_times = [t for t in self.send_times if now - t < 60]
            if len(self.send_times) >= self.store.get_rpm_limit():
                return {"ok": False, "error":"rate_limit_exceeded",
                        "rpm": self.store.get_rpm_limit()}
            self.send_times.append(now)
            u = URL(item.get("url"))
            host = u.getHost()
            use_https = (u.getProtocol() or "").lower() == "https"
            port = u.getPort()
            if port == -1: port = 443 if use_https else 80
            path = u.getPath() or "/"
            if u.getQuery(): path += "?" + u.getQuery()
            method = item.get("method","GET")
            headers = self._merge_session_headers(host, item.get("headers") or {})
            if "Host" not in headers: headers["Host"] = host
            start = method + " " + path + " HTTP/1.1\r\n"
            hdr = "".join([k + ": " + str(v) + "\r\n" for k,v in headers.items()])
            body = item.get("body") or ""
            req_str = start + hdr + "\r\n" + body
            srv = self.helpers.buildHttpService(host, port, use_https)
            resp = self.callbacks.makeHttpRequest(srv, self.helpers.stringToBytes(req_str))
            rbytes = resp.getResponse()
            if not rbytes: return {"ok":False,"error":"no_response"}
            info = self.helpers.analyzeResponse(rbytes)
            status = info.getStatusCode()
            rb = self.helpers.bytesToString(rbytes)[info.getBodyOffset():]
            def _upd():
                try:
                    self.ui.modelio_area.setText(
                        "Sent: {} {}\nStatus: {}\nBody:\n{}".format(
                            method, item.get("url"), status, rb[:2000]))
                except Exception: pass
            self._safe_ui(_upd)
            return {"ok": True, "method": method, "url": item.get("url"),
                    "status": status,
                    "body": rb[:5000] + ("...[truncated]" if len(rb) > 5000 else ""),
                    "body_length": len(rb)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _merge_session_headers(self, host, headers):
        out = dict(headers or {})
        try: items = self.callbacks.getProxyHistory()
        except Exception: items = []
        for it in reversed(items[-200:]):
            try:
                req = self.helpers.analyzeRequest(it)
                if host in str(req.getUrl()):
                    for h in req.getHeaders()[1:]:
                        i = h.find(":")
                        if i > 0:
                            k = h[:i]; v = h[i+1:].strip()
                            if k.lower() in ("cookie","authorization") and k not in out:
                                out[k] = v
                    break
            except Exception: pass
        return out

    # ---------- Queue actions ----------
    def _refresh_queue_view(self):
        try:
            if not self.queue:
                self.ui.queue_area.setText("(empty)"); return
            lines = []
            for i, item in enumerate(self.queue):
                st = "APPROVED" if item.get("approved") else "PENDING"
                extra = (" - " + item.get("rationale","")) if item.get("rationale") else ""
                lines.append("[{}] {} {} ({}){}".format(
                    i, item.get("method"), item.get("url"), st, extra))
            self.ui.queue_area.setText("\n".join(lines))
        except Exception: pass

    def _approve_next(self):
        if self.queue: self.queue[0]["approved"] = True; self._refresh_queue_view()
    def _reject_next(self):
        if self.queue: self.queue.pop(0); self._refresh_queue_view()
    def _send_next(self):
        if not self.queue: return
        item = self.queue[0]
        if not item.get("approved"):
            self._append_chat("system", "Next request not approved."); return
        self.queue.pop(0); self._refresh_queue_view()
        res = self._dispatch_request(item)
        self._append_chat("system", "Send result: " + json.dumps(res, default=str)[:400])

    # ---------- Misc UI actions ----------
    def _refresh_target(self):
        urls = self.target.list_urls()
        self.ui.target_area.setText("\n".join(urls))

    def _search_target(self):
        pref = self.ui.target_prefix.getText() or ""
        urls = self.target.list_urls_filtered(path_prefix=(pref or None), limit=1000)
        if pref: urls = [u for u in urls if pref in u]
        self.ui.target_area.setText("\n".join(urls))

    def _list_history(self):
        items = self.history.list()
        self.ui.history_area.setText("\n".join(
            ["{} {} [{} {}]".format(x.get("method"), x.get("url"),
                                    x.get("status"), x.get("mime")) for x in items]))

    def _search_history(self):
        q = self.ui.history_query.getText()
        items = self.history.search(q)
        self.ui.history_area.setText("\n".join(
            ["#{} {} {}  {}".format(x.get("index"), x.get("method"),
                                    x.get("url"), (x.get("match") or "")[:120])
             for x in items]))

    def _test_openrouter(self):
        api_key = self.ui.api_key_field.getText() or self.store.get_api_key()
        model = self.ui.model_field.getText() or self.store.get_model()
        def _bg():
            try:
                messages = [
                    {"role":"system","content":"You are a test assistant. Reply concisely."},
                    {"role":"user","content":"Reply with just: OK"}]
                # 500 tokens: reasoning models (o1, r1, dots-studio) burn tokens
                # on internal thought before producing output.
                res = self.client.chat(api_key, model, messages, tools=None,
                                       temperature=0.0, max_tokens=500)
                content = res.get("content","")
                finish = res.get("finish_reason","")
                usage = res.get("usage") or {}
                summary = ("Status: {}\nFinish: {}\nContent: {}\nUsage: {}\n\n"
                           "Debug:\n{}\n\nRaw:\n{}").format(
                    res.get("status"), finish, content[:200] or "(empty)",
                    json.dumps(usage), res.get("debug",""), res.get("raw",""))
                self._safe_ui(lambda s=summary: self.ui.modelio_area.setText(s))
            except Exception as e:
                self._safe_ui(lambda: self.ui.modelio_area.setText("Test error: " + str(e)))
        threading.Thread(target=_bg).start()

    def _list_models(self):
        api_key = self.ui.api_key_field.getText() or self.store.get_api_key()
        def _bg():
            try:
                res = self.client.list_models(api_key)
                self._safe_ui(lambda: self.ui.modelio_area.setText(
                    "Status: {}\n{}".format(res.get("status"), res.get("content",""))))
            except Exception as e:
                self._safe_ui(lambda: self.ui.modelio_area.setText("List error: " + str(e)))
        threading.Thread(target=_bg).start()

    # ---------- UI helpers ----------
    def _append_chat(self, role, text):
        def _upd():
            try:
                self.ui.renderer.add(role, text)
                self.ui.chat_view.setText(self.ui.renderer.to_html())
                try:
                    self.ui.chat_view.setCaretPosition(
                        self.ui.chat_view.getDocument().getLength())
                except Exception: pass
            except Exception: pass
        self._safe_ui(_upd)

    def _safe_ui(self, fn):
        try:
            if hasattr(SwingUtilities, "isEventDispatchThread") and \
               not SwingUtilities.isEventDispatchThread():
                SwingUtilities.invokeLater(fn)
            else: fn()
        except Exception as e:
            self._log_debug("ui update err: " + str(e))

    def _log_debug(self, text):
        try:
            if isinstance(text, bytes): text = text.decode("utf-8","replace")
            elif not isinstance(text, _string_types): text = str(text)
        except Exception: text = repr(text)
        msg = "[" + time.strftime("%H:%M:%S") + "] " + text
        try:
            if self.logger: self.logger.debug(msg)
        except Exception: pass
        def _upd():
            try:
                if hasattr(self,"ui") and self.ui and self.ui.debug_area:
                    self.ui.debug_area.append(msg + "\n")
                    try:
                        self.ui.debug_area.setCaretPosition(
                            self.ui.debug_area.getDocument().getLength())
                    except Exception: pass
            except Exception: pass
        self._safe_ui(_upd)

    def _clear_debug(self):
        try: self.ui.debug_area.setText("")
        except Exception: pass

    # ---------- Chat save/load ----------
    def _default_chat_dir(self):
        d = os.path.join(os.path.expanduser("~"), "burpai_chats")
        try:
            if not os.path.exists(d): os.makedirs(d)
        except Exception: pass
        return d

    def _quick_save_chat(self):
        try:
            d = self._default_chat_dir()
            ts = time.strftime("%Y%m%d_%H%M%S")
            p = os.path.join(d, "chat_" + ts + ".html")
            with open(p, "wb") as f:
                f.write(self.ui.chat_view.getText().encode("utf-8"))
            with open(os.path.join(d, "conv_" + ts + ".json"), "wb") as f:
                f.write(json.dumps(self.conversation.get_messages(), default=str).encode("utf-8"))
            JOptionPane.showMessageDialog(self.ui.root, "Saved: " + p)
        except Exception as e:
            JOptionPane.showMessageDialog(self.ui.root, "Save error: " + str(e))

    def _quick_load_chat(self):
        try:
            d = self._default_chat_dir()
            files = sorted([os.path.join(d, x) for x in os.listdir(d) if x.endswith('.html')])
            if not files: return
            p = files[-1]
            with open(p, "rb") as f:
                self.ui.chat_view.setText(f.read().decode("utf-8"))
        except Exception as e:
            try: self.ui.modelio_area.setText("Load error: " + str(e))
            except Exception: pass
