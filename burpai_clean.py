# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import JPanel, JButton, JTextField, JTextArea, JScrollPane, JTabbedPane, JLabel, JEditorPane, JSplitPane, JOptionPane, JCheckBox, SwingUtilities
from javax.swing.text.html import HTMLEditorKit
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
from java.awt import Color
from java.awt.event import ActionListener
import os
import json
import time
import re
import threading
import traceback
import java.io
from java.net import URL

try:
    from urllib2 import Request, urlopen, HTTPError, URLError
except ImportError:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError



class Logger(object):
    def __init__(self, callbacks=None):
        self.callbacks = callbacks
        self.stdout = None
        self.stderr = None
        if callbacks:
            try:
                self.stdout = java.io.PrintWriter(callbacks.getStdout(), True)
                self.stderr = java.io.PrintWriter(callbacks.getStderr(), True)
            except Exception:
                pass

    def info(self, msg):
        try:
            m = "[INFO] " + str(msg)
            if self.stdout:
                self.stdout.println(m)
            else:
                print(m)
        except Exception:
            pass

    def error(self, msg, exc=None):
        try:
            m = "[ERROR] " + str(msg)
            if exc:
                m += ": " + str(exc)
            if self.stderr:
                self.stderr.println(m)
                if exc:
                    traceback.print_exc(file=self.stderr)
            else:
                print(m)
                if exc:
                    traceback.print_exc()
        except Exception:
            pass

    def debug(self, msg):
        try:
            m = "[DEBUG] " + str(msg)
            if self.stdout:
                self.stdout.println(m)
            else:
                print(m)
        except Exception:
            pass


class SettingsStore(object):
    def __init__(self, logger=None):
        self.path = os.path.join(os.path.expanduser("~"), ".burpai_config.json")
        self.data = {}
        self.logger = logger
        self._load()

    def _log_err(self, msg, e):
        if self.logger:
            self.logger.error(msg, e)
        else:
            print(msg + ": " + str(e))

    def _load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "rb") as f:
                    self.data = json.loads(f.read().decode("utf-8"))
        except Exception as e:
            self.data = {}
            self._log_err("Settings load error", e)

    def _save(self):
        try:
            with open(self.path, "wb") as f:
                f.write(json.dumps(self.data, ensure_ascii=False, indent=2).encode("utf-8"))
        except Exception as e:
            self._log_err("Settings save error", e)

    def get_api_key(self):
        v = self.data.get("openrouter_api_key")
        if v:
            return v
        return os.environ.get("OPENROUTER_API_KEY", "")

    def set_api_key(self, v):
        self.data["openrouter_api_key"] = v or ""
        self._save()

    def get_model(self):
        return self.data.get("model_name", "openrouter/auto")

    def set_model(self, v):
        self.data["model_name"] = v or "openrouter/auto"
        self._save()

    def get_system_prompt(self):
        v = self.data.get("system_prompt")
        try:
            if not v:
                return self._default_system_prompt()
            lv = v.strip().lower()
            if lv in (
                "you are a helpful assistant.",
                "you are a helpful assistant",
                "you are a helpful security assistant.",
                "you are a helpful security assistant",
            ):
                return self._default_system_prompt()
        except Exception:
            pass
        return v

    def set_system_prompt(self, v):
        self.data["system_prompt"] = v or ""
        self._save()

    def get_notebook_path(self):
        return self.data.get("notebook_path", os.path.join(os.path.expanduser("~"), "burpai_notebook.txt"))

    def set_notebook_path(self, v):
        self.data["notebook_path"] = v or os.path.join(os.path.expanduser("~"), "burpai_notebook.txt")
        self._save()

    def get_rpm_limit(self):
        return int(self.data.get("rpm_limit", 30))

    def set_rpm_limit(self, v):
        try:
            self.data["rpm_limit"] = int(v)
        except Exception as e:
            self.data["rpm_limit"] = 30
            self._log_err("RPM parse error", e)
        self._save()

    def get_strict_json_mode(self):
        try:
            return bool(self.data.get("strict_json_mode", False))
        except Exception:
            return False

    def set_strict_json_mode(self, v):
        try:
            self.data["strict_json_mode"] = bool(v)
        except Exception:
            self.data["strict_json_mode"] = False
        self._save()

    def get_auto_mode(self):
        try:
            return bool(self.data.get("auto_mode", True))
        except Exception:
            return True

    def set_auto_mode(self, v):
        try:
            self.data["auto_mode"] = bool(v)
        except Exception:
            self.data["auto_mode"] = False
        self._save()

    def get_auto_iterations(self):
        try:
            return int(self.data.get("auto_iterations", 10))
        except Exception:
            return 10

    def set_auto_iterations(self, v):
        try:
            self.data["auto_iterations"] = int(v)
        except Exception:
            self.data["auto_iterations"] = 10
        self._save()

    def get_auto_adaptive(self):
        try:
            return bool(self.data.get("auto_adaptive", True))
        except Exception:
            return True

    def set_auto_adaptive(self, v):
        try:
            self.data["auto_adaptive"] = bool(v)
        except Exception:
            self.data["auto_adaptive"] = True
        self._save()

    def get_large_context_mode(self):
        try:
            return bool(self.data.get("large_context_mode", False))
        except Exception:
            return False

    def set_large_context_mode(self, v):
        try:
            self.data["large_context_mode"] = bool(v)
        except Exception:
            self.data["large_context_mode"] = False
        self._save()

    def get_large_context_base_url(self):
        try:
            return str(self.data.get("large_context_base_url", ""))
        except Exception:
            return ""

    def set_large_context_base_url(self, v):
        try:
            self.data["large_context_base_url"] = str(v)
        except Exception:
            self.data["large_context_base_url"] = ""
        self._save()

    def get_large_context_max_depth(self):
        try:
            return int(self.data.get("large_context_max_depth", -1))
        except Exception:
            return -1

    def set_large_context_max_depth(self, v):
        try:
            self.data["large_context_max_depth"] = int(v)
        except Exception:
            self.data["large_context_max_depth"] = -1
        self._save()

    def get_large_context_respect_scope(self):
        try:
            return bool(self.data.get("large_context_respect_scope", True))
        except Exception:
            return True

    def set_large_context_respect_scope(self, v):
        try:
            self.data["large_context_respect_scope"] = bool(v)
        except Exception:
            self.data["large_context_respect_scope"] = True
        self._save()

    def get_large_context_include_bodies(self):
        try:
            return bool(self.data.get("large_context_include_bodies", True))
        except Exception:
            return True

    def set_large_context_include_bodies(self, v):
        try:
            self.data["large_context_include_bodies"] = bool(v)
        except Exception:
            self.data["large_context_include_bodies"] = True
        self._save()

    def get_large_context_limit(self):
        try:
            return int(self.data.get("large_context_limit", -1))
        except Exception:
            return -1

    def set_large_context_limit(self, v):
        try:
            self.data["large_context_limit"] = int(v)
        except Exception:
            self.data["large_context_limit"] = -1
        self._save()

    def _default_system_prompt(self):
        return (
            "You are BurpAI, an embedded security analyst operating inside Burp Suite.\n"
            "Mode:\n"
            "- Propose or send requests based on runtime guardrails; only send when allowed.\n"
            "- Respect Burp scope, rate limits, and any kill switch. Prioritize evidence-driven actions.\n"
            "- If the user says 'scope is everything', 'ignore scope', or similar, explicitly set respect_scope=False in your tool calls.\n"
            "- If asked to 'recreate request' and no specific index/URL is given, search for the most recent relevant requests or list the last few history items. Do not assume 'deep think mode' is a URL path unless explicitly stated.\n"
            "Outputs:\n"
            "- For natural language tasks: produce a concise reply plus optional tool_calls for next actions.\n"
            "- For structured tasks: return exactly one strict JSON object (no code fences).\n"
            "- Valid keys include: site_map, features, endpoints, api_docs, internal_features, client_vulns, proposals, requests, notes, todos, plan, tool_calls.\n"
            "Tools:\n"
            "- tool_calls: {tool: 'list_target_sitemap'|'get_target_entry'|'search_target'|'search_http'|'get_http_entry'|'get_http_body'|'list_http_sitemap'|'get_http_body_by_url'|'build_context_pack'|'get_context_pack'|'clear_context_pack'|'propose_request'|'send_request'|'note'|'append_notebook', args: {...}}.\n"
            "- list_target_sitemap: {path_prefix?: string, max_depth?: number, respect_scope?: boolean, limit?: number} → returns items [{index, method, url, status, mime, length, relative_depth}].\n"
            "- search_target: {query: string, path_prefix?: string, max_depth?: number, host_sub?: string, respect_scope?: boolean, limit?: number} → returns URL items.\n"
            "- get_target_entry: {by: 'index'|'url', value}.\n"
            "- search_http: {query: string, respect_scope?: boolean, limit?: number, in_body?: boolean, in_req?: boolean, in_headers?: boolean, regex?: boolean, status_min?: number, status_max?: number, mime_sub?: string, host_sub?: string} → returns history items matching query in URL, headers, or body (default searches ALL). Set specific flags (e.g. in_headers:true) to narrow scope.\n"
            "- get_http_entry: {index: number}.\n"
            "- get_http_body: {index: number, offset?: number, limit?: number} → returns full or ranged response body.\n"
            "- list_http_sitemap: {base_url?: string, host?: string, path_prefix?: string, max_depth?: number, respect_scope?: boolean, limit?: number} → returns unique endpoints with relative_depth and index.\n"
            "- get_http_body_by_url: {url?: string, urls?: string[], offset?: number, limit?: number} → returns bodies for matching URLs.\n"
            "- build_context_pack: {base_url?: string, max_depth?: number, respect_scope?: boolean, include_bodies?: boolean, limit?: number}.\n"
            "- get_context_pack: {} → returns giant aggregated content for model context.\n"
            "- clear_context_pack: {}.\n"
            "- propose_request: include method,url,headers,body,rationale,confidence.\n"
            "- send_request: include method,url,headers,body; honor guardrails.\n"
            "- note|append_notebook: {text}.\n"
            "Reasoning:\n"
            "- Provide a `thinking` field with detailed chain-of-thought reasoning. Analyze the situation, plan your steps, and justify your actions. Do not be brief.\n"
            "Quality:\n"
            "- Cite evidence and URLs; mark unknowns explicitly. Use file references like file_path:line_number when applicable.\n"
            "- Deduplicate endpoints (method+path) and limit lists to 50 items.\n"
            "If no relevant results are found, say 'No relevant results found yet' and propose next steps via tool_calls. Try broadening your search (e.g. respect_scope=False) if appropriate.\n"
            "User messages may include TOOL_RESULTS (JSON array) containing the last tool outputs for chaining.\n"
            "Guidance:\n"
            "- For keyword searches in content, prefer search_http with in_body:true (and in_headers:true/in_req:true if needed). Use search_target for URL enumeration and prefix/depth filtering.\n"
            "Agent Control (autonomous mode):\n"
            "- When exploring, return a single JSON with optional keys: {thinking, tool_calls, continue, reason_brief, confidence}.\n"
            "- If continue=false or a final answer is ready, include {reply} and omit further tool_calls.\n"
            "- Use continue=true (or next=true) only when proposing useful next tool_calls.\n"
            "Examples:\n"
            "{\"thinking\":\"I need to enumerate the target to find login pages, then I will narrow down by keywords.\",\"reply\":\"Listing target entries...\",\"tool_calls\":[{\"tool\":\"list_target_sitemap\",\"args\":{}},{\"tool\":\"search_target\",\"args\":{\"query\":\"login\"}}]}\n"
            "{\"thinking\":\"The top entry looks interesting. I will inspect the details to see if there are any vulnerabilities.\",\"reply\":\"Inspecting details...\",\"tool_calls\":[{\"tool\":\"get_http_entry\",\"args\":{\"index\":42}}]}\n"
            "{\"thinking\":\"I suspect a SQL injection vulnerability. I will propose a test request to verify this.\",\"reply\":\"Queuing...\",\"tool_calls\":[{\"tool\":\"propose_request\",\"args\":{\"method\":\"POST\",\"url\":\"https://example.com/api/login\",\"headers\":{\"Content-Type\":\"application/json\"},\"body\":\"{\\\"user\\\":\\\"alice\\\",\\\"pass\\\":\\\"test\\\"}\"}}]}\n"
        )


class HtmlRenderer(object):
    def __init__(self):
        self.html = ["<html><body style='font-family: Segoe UI, sans-serif; font-size: 12px; background:#111; color:#ddd;'>"]

    def _escape(self, s):
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def add(self, role, text):
        t = self._escape(text)
        if role == "user":
            self.html.append("<div style='background:#222;padding:8px;border-radius:6px;margin:6px 0'><b>User</b><div>" + t + "</div></div>")
        else:
            self.html.append("<div style='background:#1b2a1b;padding:8px;border-radius:6px;margin:6px 0'><b>Assistant</b><div>" + t + "</div></div>")

    def to_html(self):
        return "".join(self.html) + "</body></html>"


class OpenRouterClient(object):
    def __init__(self, callbacks, logger=None):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.logger = logger
        self.host = "openrouter.ai"
        self.port = 443
        self.use_https = True
        self.path_chat = "/api/v1/chat/completions"
        self.path_comp = "/api/v1/completions"
        self.path_models = "/api/v1/models"
        self.debug_logger = None

    def set_debug_logger(self, logger):
        self.debug_logger = logger

    def _log(self, text):
        try:
            msg = str(text)
            if self.debug_logger:
                self.debug_logger(msg)
        except Exception:
            pass

    def call(self, api_key, model, system_prompt, user_text):
        if not api_key:
            return {"ok": False, "content": "Missing API key", "raw": "", "status": 0, "debug": "missing_api_key"}
        try:
            self._log("[call] start model=" + str(model or "openrouter/auto") + ", system_len=" + str(len(system_prompt or "")) + ", user_len=" + str(len(user_text or "")))
        except Exception:
            pass
        chat = self._call_chat(api_key, model, system_prompt, user_text)
        if chat.get("ok"):
            try:
                self._log("[call] chat ok")
            except Exception:
                pass
            return chat
        try:
            self._log("[call] chat failed; fallback to completions")
        except Exception:
            pass
        comp = self._call_completions(api_key, model, system_prompt, user_text)
        dbg = chat.get("debug")
        if dbg:
            comp["debug"] = (dbg + "\n\n" + (comp.get("debug") or ""))
        return comp

    def list_models(self, api_key):
        if not api_key:
            return {"ok": False, "content": "Missing API key", "raw": "", "status": 0, "debug": "missing_api_key"}
        try:
            url = "https://" + self.host + self.path_models
            req = Request(url)
            dbg_headers = []
            dbg_headers.append("Accept: application/json")
            req.add_header("Authorization", "Bearer " + api_key)
            req.add_header("Accept", "application/json")
            ref = os.environ.get("OPENROUTER_HTTP_REFERER")
            ttl = os.environ.get("OPENROUTER_X_TITLE")
            if ref:
                req.add_header("HTTP-Referer", ref)
                dbg_headers.append("HTTP-Referer: " + str(ref))
            if ttl:
                req.add_header("X-Title", ttl)
                dbg_headers.append("X-Title: " + str(ttl))
            dbg = []
            dbg.append("endpoint: " + url)
            dbg.append("headers: " + "; ".join(dbg_headers))
            try:
                self._log("[list_models] " + "\n".join(dbg))
                raw = urlopen(req, timeout=25).read()
                txt = raw.decode("utf-8", "ignore")
                self._log("[list_models] status: 200")
                self._log("[list_models] raw: " + txt)
                return {"ok": True, "content": txt, "raw": txt, "status": 200, "debug": "\n".join(dbg) + "\nstatus: 200"}
            except HTTPError as e:
                try:
                    body = e.read()
                except Exception:
                    body = b""
                dbg.append("status: " + str(getattr(e, "code", 0)))
                dbg.append("error: " + str(e))
                try:
                    self._log("[list_models] " + "\n".join(dbg))
                    self._log("[list_models] raw: " + body.decode("utf-8", "ignore"))
                except Exception:
                    pass
                return {"ok": False, "content": str(e), "raw": body.decode("utf-8", "ignore"), "status": getattr(e, "code", 0), "debug": "\n".join(dbg)}
            except URLError as e:
                dbg.append("error: " + str(e))
                try:
                    self._log("[list_models] " + "\n".join(dbg))
                except Exception:
                    pass
                return {"ok": False, "content": str(e), "raw": "", "status": 0, "debug": "\n".join(dbg)}
        except Exception as e:
            try:
                self._log("[list_models] exception: " + str(e))
                self._log("[list_models] trace: " + traceback.format_exc())
            except Exception:
                pass
            return {"ok": False, "content": str(e), "raw": "", "status": 0, "debug": traceback.format_exc()}

    def _call_chat(self, api_key, model, system_prompt, user_text):
        payload = {
            "model": model or "openrouter/auto",
            "messages": [
                {"role": "system", "content": system_prompt or ""},
                {"role": "user", "content": user_text or ""},
            ]
        }
        url = "https://" + self.host + self.path_chat
        req = Request(url)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        req.add_header("Authorization", "Bearer " + api_key)
        ref = os.environ.get("OPENROUTER_HTTP_REFERER")
        ttl = os.environ.get("OPENROUTER_X_TITLE")
        if ref:
            req.add_header("HTTP-Referer", ref)
        if ttl:
            req.add_header("X-Title", ttl)
        try:
            dbg = []
            dbg.append("endpoint: " + url)
            dbg.append("model: " + str(model or "openrouter/auto"))
            dbg.append("headers: Content-Type: application/json; Accept: application/json")
            if ref:
                dbg.append("HTTP-Referer: " + str(ref))
            if ttl:
                dbg.append("X-Title: " + str(ttl))
            body_bytes = json.dumps(payload).encode("utf-8")
            dbg.append("payload_len: " + str(len(body_bytes)))
            dbg.append("payload: " + json.dumps(payload))
            try:
                self._log("[chat] " + "\n".join(dbg))
            except Exception:
                pass
            raw = urlopen(req, body_bytes, timeout=25).read()
            txt = raw.decode("utf-8", "ignore")
            try:
                self._log("[chat] raw: " + txt)
            except Exception:
                pass
            data = {}
            try:
                data = json.loads(txt)
            except Exception as e:
                try:
                    print("OpenRouter parse error: " + str(e))
                except Exception:
                    pass
            if isinstance(data, dict) and data.get("error"):
                msg = str(data.get("error"))
                dbg.append("status: 400")
                dbg.append("error: " + msg)
                return {"ok": False, "content": msg, "raw": txt, "status": 400, "debug": "\n".join(dbg)}
            c = (data.get("choices") or []) if isinstance(data, dict) else []
            if c:
                m = c[0].get("message") or {}
                dbg.append("status: 200")
                dbg.append("choices_len: " + str(len(c)))
                try:
                    self._log("[chat] status: 200")
                    self._log("[chat] choices_len: " + str(len(c)))
                    self._log("[chat] content_len: " + str(len(m.get("content", ""))))
                except Exception:
                    pass
                return {"ok": True, "content": m.get("content", ""), "raw": txt, "status": 200, "debug": "\n".join(dbg)}
            dbg.append("status: 200")
            dbg.append("choices_len: 0")
            try:
                self._log("[chat] status: 200")
                self._log("[chat] choices_len: 0")
            except Exception:
                pass
            return {"ok": False, "content": "Empty choices", "raw": txt, "status": 200, "debug": "\n".join(dbg)}
        except HTTPError as e:
            dbg = []
            dbg.append("endpoint: " + url)
            try:
                body = e.read()
            except Exception:
                body = b""
            dbg.append("status: " + str(getattr(e, "code", 0)))
            dbg.append("error: " + str(e))
            try:
                self._log("[chat] " + "\n".join(dbg))
                self._log("[chat] raw: " + body.decode("utf-8", "ignore"))
            except Exception:
                pass
            return {"ok": False, "content": str(e), "raw": body.decode("utf-8", "ignore"), "status": getattr(e, "code", 0), "debug": "\n".join(dbg)}
        except URLError as e:
            dbg = []
            dbg.append("endpoint: " + url)
            dbg.append("error: " + str(e))
            try:
                self._log("[chat] " + "\n".join(dbg))
            except Exception:
                pass
            return {"ok": False, "content": str(e), "raw": "", "status": 0, "debug": "\n".join(dbg)}
        except Exception as e:
            dbg = []
            dbg.append("endpoint: " + url)
            dbg.append("exception: " + str(e))
            dbg.append("trace: " + traceback.format_exc())
            try:
                self._log("[chat] " + "\n".join(dbg))
            except Exception:
                pass
            return {"ok": False, "content": str(e), "raw": "", "status": 0, "debug": "\n".join(dbg)}

    def _call_completions(self, api_key, model, system_prompt, user_text):
        full_prompt = (system_prompt or "") + ("\n\n" if system_prompt else "") + (user_text or "")
        payload = {
            "model": model or "openrouter/auto",
            "prompt": full_prompt,
            "max_tokens": 512,
            "temperature": 0.3,
        }
        url = "https://" + self.host + self.path_comp
        req = Request(url)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        req.add_header("Authorization", "Bearer " + api_key)
        ref = os.environ.get("OPENROUTER_HTTP_REFERER")
        ttl = os.environ.get("OPENROUTER_X_TITLE")
        if ref:
            req.add_header("HTTP-Referer", ref)
        if ttl:
            req.add_header("X-Title", ttl)
        try:
            dbg = []
            dbg.append("endpoint: " + url)
            dbg.append("model: " + str(model or "openrouter/auto"))
            dbg.append("headers: Content-Type: application/json; Accept: application/json")
            if ref:
                dbg.append("HTTP-Referer: " + str(ref))
            if ttl:
                dbg.append("X-Title: " + str(ttl))
            body_bytes = json.dumps(payload).encode("utf-8")
            dbg.append("payload_len: " + str(len(body_bytes)))
            dbg.append("payload: " + json.dumps(payload))
            try:
                self._log("[completions] " + "\n".join(dbg))
            except Exception:
                pass
            raw = urlopen(req, body_bytes, timeout=25).read()
            txt = raw.decode("utf-8", "ignore")
            try:
                self._log("[completions] raw: " + txt)
            except Exception:
                pass
            data = {}
            try:
                data = json.loads(txt)
            except Exception as e:
                try:
                    print("OpenRouter parse error: " + str(e))
                except Exception:
                    pass
            if isinstance(data, dict) and data.get("error"):
                msg = str(data.get("error"))
                dbg.append("status: 400")
                dbg.append("error: " + msg)
                return {"ok": False, "content": msg, "raw": txt, "status": 400, "debug": "\n".join(dbg)}
            c = (data.get("choices") or []) if isinstance(data, dict) else []
            if c:
                if "text" in c[0]:
                    dbg.append("status: 200")
                    dbg.append("choices_len: " + str(len(c)))
                    try:
                        self._log("[completions] status: 200")
                        self._log("[completions] choices_len: " + str(len(c)))
                        self._log("[completions] content_len: " + str(len(c[0].get("text", ""))))
                    except Exception:
                        pass
                    return {"ok": True, "content": c[0].get("text", ""), "raw": txt, "status": 200, "debug": "\n".join(dbg)}
                m = c[0].get("message") or {}
                dbg.append("status: 200")
                dbg.append("choices_len: " + str(len(c)))
                try:
                    self._log("[completions] status: 200")
                    self._log("[completions] choices_len: " + str(len(c)))
                    self._log("[completions] content_len: " + str(len(m.get("content", ""))))
                except Exception:
                    pass
                return {"ok": True, "content": m.get("content", ""), "raw": txt, "status": 200, "debug": "\n".join(dbg)}
            dbg.append("status: 200")
            dbg.append("choices_len: 0")
            try:
                self._log("[completions] status: 200")
                self._log("[completions] choices_len: 0")
            except Exception:
                pass
            return {"ok": False, "content": "Empty choices", "raw": txt, "status": 200, "debug": "\n".join(dbg)}
        except HTTPError as e:
            dbg = []
            dbg.append("endpoint: " + url)
            try:
                body = e.read()
            except Exception:
                body = b""
            dbg.append("status: " + str(getattr(e, "code", 0)))
            dbg.append("error: " + str(e))
            try:
                self._log("[completions] " + "\n".join(dbg))
                self._log("[completions] raw: " + body.decode("utf-8", "ignore"))
            except Exception:
                pass
            return {"ok": False, "content": str(e), "raw": body.decode("utf-8", "ignore"), "status": getattr(e, "code", 0), "debug": "\n".join(dbg)}
        except URLError as e:
            dbg = []
            dbg.append("endpoint: " + url)
            dbg.append("error: " + str(e))
            try:
                self._log("[completions] " + "\n".join(dbg))
            except Exception:
                pass
            return {"ok": False, "content": str(e), "raw": "", "status": 0, "debug": "\n".join(dbg)}
        except Exception as e:
            dbg = []
            dbg.append("endpoint: " + url)
            dbg.append("exception: " + str(e))
            dbg.append("trace: " + traceback.format_exc())
            try:
                self._log("[completions] " + "\n".join(dbg))
            except Exception:
                pass
            return {"ok": False, "content": str(e), "raw": "", "status": 0, "debug": "\n".join(dbg)}
        


class TargetHelper(object):
    def __init__(self, callbacks, logger=None):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.logger = logger

    def list_urls(self):
        try:
            items = self.callbacks.getSiteMap(None)
        except Exception as e:
            items = []
            if self.logger:
                self.logger.error("SiteMap error", e)
        out = []
        for it in items[:500]:
            try:
                url = self.helpers.analyzeRequest(it).getUrl()
                out.append(str(url))
            except Exception as e:
                if self.logger:
                    self.logger.error("List url error", e)
        return out

    def list_urls_filtered(self, path_prefix=None, max_depth=-1, respect_scope=True, limit=500, host_sub=None):
        try:
            items = self.callbacks.getSiteMap(None)
        except Exception as e:
            items = []
            if self.logger:
                self.logger.error("SiteMap error", e)
        out = []
        base_seg_len = 0
        try:
            if path_prefix:
                base_seg_len = len([s for s in str(path_prefix).split('/') if len(s)>0])
        except Exception:
            base_seg_len = 0
        for it in items:
            try:
                url = self.helpers.analyzeRequest(it).getUrl()
                if respect_scope:
                    try:
                        if not self.callbacks.isInScope(url):
                            continue
                    except Exception:
                        pass
                try:
                    if host_sub and host_sub.lower() not in (url.getHost() or "").lower():
                        continue
                except Exception:
                    pass
                p = ''
                try:
                    p = url.getPath() if hasattr(url, 'getPath') else str(url)
                except Exception:
                    p = str(url)
                if path_prefix and not p.startswith(path_prefix):
                    continue
                segs = [s for s in p.split('/') if len(s)>0]
                rel_depth = max(0, len(segs) - base_seg_len)
                if max_depth >= 0 and rel_depth > max_depth:
                    continue
                out.append(str(url))
                if len(out) >= limit:
                    break
            except Exception:
                pass
        return out


class HttpHistoryHelper(object):
    def __init__(self, callbacks, logger=None):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.logger = logger

    def list(self, limit=500):
        try:
            items = self.callbacks.getProxyHistory()
        except Exception as e:
            items = []
            if self.logger:
                self.logger.error("Proxy history error", e)
        out = []
        for it in items[-limit:]:
            try:
                req = self.helpers.analyzeRequest(it)
                url = req.getUrl()
                method = req.getMethod()
                resp = it.getResponse()
                status = 0
                mime = ""
                if resp:
                    ri = self.helpers.analyzeResponse(resp)
                    status = ri.getStatusCode()
                    mime = ri.getStatedMimeType()
                out.append({"method": method, "url": str(url), "status": status, "mime": str(mime)})
            except Exception as e:
                if self.logger:
                    self.logger.error("History list error", e)
        return out

    def search(self, query, limit=200, respect_scope=True, in_body=False, in_req=False, in_headers=False, regex=False, status_min=0, status_max=999, mime_sub="", host_sub=""):
        q = (query or "")
        if not regex:
            q = q.lower()
        
        # If no specific flags are set, search everything (browser-like behavior)
        if not (in_body or in_req or in_headers):
            in_body = True
            in_req = True
            in_headers = True

        results = []
        try:
            items = self.callbacks.getProxyHistory()
        except Exception as e:
            items = []
            try:
                print("Proxy history error: " + str(e))
            except Exception:
                pass
        
        patt = None
        if regex:
            try:
                import re as _re
                patt = _re.compile(query, _re.IGNORECASE)
            except Exception:
                patt = None

        for idx in range(len(items)-1, -1, -1):
            it = items[idx]
            try:
                # 1. Fast scope/host check using URL only (lightweight)
                req_info = None # Lazy load
                
                # We need at least the URL to check scope/host
                # To avoid full analyzeRequest, we can try to grab URL from wrapper if possible, 
                # but analyzeRequest is usually fast enough for just URL. 
                # Let's do it, but defer body analysis.
                req_info = self.helpers.analyzeRequest(it)
                uo = req_info.getUrl()
                url = str(uo)

                if respect_scope:
                    try:
                        if not self.callbacks.isInScope(uo):
                            continue
                    except Exception:
                        pass
                try:
                    if host_sub and host_sub.lower() not in (uo.getHost() or "").lower():
                        continue
                except Exception:
                    pass

                # 2. Search Logic
                matched = False
                match_snip = ""
                
                # URL Search
                if patt:
                    if patt.search(url):
                        matched = True
                        match_snip = "URL: " + url
                else:
                    if q in url.lower():
                        matched = True
                        match_snip = "URL: " + url

                # Request Search (Headers + Body)
                if not matched and in_req:
                    try:
                        # Get raw request bytes -> string
                        raw_req = self.helpers.bytesToString(it.getRequest())
                        if patt:
                            m = patt.search(raw_req)
                            if m:
                                matched = True
                                p = m.start(); s = max(0, p-80); e = min(len(raw_req), p+80)
                                match_snip = "REQ: " + raw_req[s:e].replace("\n"," ")
                        else:
                            if q in raw_req.lower():
                                matched = True
                                p = raw_req.lower().find(q)
                                s = max(0, p-80); e = min(len(raw_req), p+80)
                                match_snip = "REQ: " + raw_req[s:e].replace("\n"," ")
                    except Exception:
                        pass

                # Response Search (Headers + Body)
                # We treat headers and body together for speed if both are requested, 
                # or separate if needed. But "in_body" usually implies "in response".
                # If user wanted ONLY headers, we'd need to split. 
                # But for "search everything", raw search is best.
                
                if not matched and (in_body or in_headers):
                    resp_bytes = it.getResponse()
                    if resp_bytes:
                        try:
                            # Check status/mime constraints first if they exist
                            # This requires parsing, which slows us down. 
                            # Only parse if we have constraints.
                            if (status_min > 0 or status_max < 999 or mime_sub):
                                resp_info = self.helpers.analyzeResponse(resp_bytes)
                                st = resp_info.getStatusCode()
                                mt = resp_info.getStatedMimeType() or ""
                                if st < status_min or st > status_max:
                                    continue
                                if mime_sub and mime_sub.lower() not in mt.lower():
                                    continue
                            
                            # Raw search
                            raw_resp = self.helpers.bytesToString(resp_bytes)
                            if patt:
                                m = patt.search(raw_resp)
                                if m:
                                    matched = True
                                    p = m.start(); s = max(0, p-80); e = min(len(raw_resp), p+80)
                                    match_snip = "RESP: " + raw_resp[s:e].replace("\n"," ")
                            else:
                                if q in raw_resp.lower():
                                    matched = True
                                    p = raw_resp.lower().find(q)
                                    s = max(0, p-80); e = min(len(raw_resp), p+80)
                                    match_snip = "RESP: " + raw_resp[s:e].replace("\n"," ")
                        except Exception:
                            pass

                if matched:
                    # Get basic info for result
                    method = req_info.getMethod()
                    status = 0
                    mime = ""
                    # If we haven't parsed response yet, do it now for the report
                    if it.getResponse():
                        try:
                            ri = self.helpers.analyzeResponse(it.getResponse())
                            status = ri.getStatusCode()
                            mime = ri.getStatedMimeType()
                        except Exception:
                            pass
                    
                    results.append({
                        "source": "history", 
                        "index": idx, 
                        "url": url, 
                        "method": method, 
                        "status": status, 
                        "mime": str(mime), 
                        "match": match_snip
                    })

                if len(results) >= limit:
                    break
            except Exception as e:
                if self.logger:
                    self.logger.error("History search error", e)
        return results

    def get_entry(self, index):
        try:
            items = self.callbacks.getProxyHistory()
            if index < 0 or index >= len(items):
                return None
            it = items[index]
            req = self.helpers.analyzeRequest(it)
            url = str(req.getUrl())
            method = req.getMethod()
            resp = it.getResponse()
            status = 0
            mime = ""
            body = ""
            if resp:
                ri = self.helpers.analyzeResponse(resp)
                status = ri.getStatusCode()
                mime = ri.getStatedMimeType()
                s = ri.getBodyOffset()
                body = self.helpers.bytesToString(resp)[s:]
            return {"url": url, "method": method, "status": status, "mime": str(mime), "body": body[:2000]}
        except Exception as e:
            if self.logger:
                self.logger.error("History get entry error", e)
            return None

    def get_body(self, index, offset=0, limit=-1):
        try:
            items = self.callbacks.getProxyHistory()
            if index < 0 or index >= len(items):
                return None
            it = items[index]
            resp = it.getResponse()
            if not resp:
                return ""
            ri = self.helpers.analyzeResponse(resp)
            s = ri.getBodyOffset()
            body = self.helpers.bytesToString(resp)[s:]
            try:
                off = int(offset or 0)
            except Exception:
                off = 0
            try:
                lim = int(limit or -1)
            except Exception:
                lim = -1
            if off < 0:
                off = 0
            if lim is None or lim <= 0:
                return body[off:]
            return body[off:off+lim]
        except Exception:
            return None

    def list_sitemap(self, host=None, path_prefix=None, max_depth=-1, respect_scope=True, limit=500):
        try:
            items = self.callbacks.getProxyHistory()
        except Exception as e:
            items = []
            if self.logger:
                self.logger.error("Proxy history error", e)
        out = []
        seen = set()
        base_seg_len = 0
        try:
            if path_prefix:
                base_seg_len = len([s for s in str(path_prefix).split('/') if len(s)>0])
        except Exception:
            base_seg_len = 0
        for idx in range(len(items)-1, -1, -1):
            it = items[idx]
            try:
                req = self.helpers.analyzeRequest(it)
                uo = req.getUrl()
                try:
                    if host and host.lower() not in (uo.getHost() or "").lower():
                        continue
                except Exception:
                    pass
                if respect_scope:
                    try:
                        if not self.callbacks.isInScope(uo):
                            continue
                    except Exception:
                        pass
                p = ''
                try:
                    p = uo.getPath() if hasattr(uo, 'getPath') else str(uo)
                except Exception:
                    p = str(uo)
                if path_prefix and not p.startswith(path_prefix):
                    continue
                segs = [s for s in p.split('/') if len(s)>0]
                rel_depth = max(0, len(segs) - base_seg_len)
                if max_depth >= 0 and rel_depth > max_depth:
                    continue
                key = (req.getMethod() or '') + ' ' + p
                if key in seen:
                    continue
                seen.add(key)
                rs = it.getResponse()
                status = 0
                mime = ''
                if rs:
                    try:
                        rinfo = self.helpers.analyzeResponse(rs)
                        status = rinfo.getStatusCode()
                        mime = rinfo.getStatedMimeType() or ''
                    except Exception:
                        pass
                out.append({"index": idx, "method": req.getMethod(), "url": str(uo), "status": status, "mime": str(mime), "relative_depth": rel_depth})
                if len(out) >= limit:
                    break
            except Exception:
                pass
        return out

    def get_body_by_url(self, url, offset=0, limit=-1):
        try:
            items = self.callbacks.getProxyHistory()
        except Exception as e:
            items = []
            if self.logger:
                self.logger.error("Proxy history error", e)
        idx_match = -1
        for idx in range(len(items)-1, -1, -1):
            it = items[idx]
            try:
                req = self.helpers.analyzeRequest(it)
                u = str(req.getUrl())
                if u == url:
                    idx_match = idx
                    break
            except Exception:
                pass
        if idx_match == -1:
            return None
        return self.get_body(idx_match, offset=offset, limit=limit)


class JsonUtils(object):
    def extract_json(self, text):
        if not text:
            return None
        s = text.strip()
        try:
            if s.startswith("{"):
                return json.loads(s)
        except Exception as e:
            try:
                print("JSON parse error: " + str(e))
            except Exception:
                pass
        try:
            start = s.find("{")
            end = s.rfind("}")
            if start != -1 and end != -1 and end > start:
                return json.loads(s[start:end + 1])
        except Exception as e:
            try:
                print("JSON extract error: " + str(e))
            except Exception:
                pass
        return None

    def _balanced(self, s, open_ch, close_ch):
        try:
            t = str(s)
        except Exception:
            t = ""
        i0 = t.find(open_ch)
        if i0 == -1:
            return None
        d = 0
        ins = False
        esc = False
        for i in range(i0, len(t)):
            ch = t[i]
            if ins:
                if esc:
                    esc = False
                elif ch == '\\':
                    esc = True
                elif ch == '"':
                    ins = False
            else:
                if ch == '"':
                    ins = True
                elif ch == open_ch:
                    d += 1
                elif ch == close_ch:
                    d -= 1
                    if d == 0:
                        return t[i0:i+1]
        return None

    def extract_json_any(self, text):
        if not text:
            return None
        s = str(text).strip()
        try:
            return json.loads(s)
        except Exception:
            pass
        seg = self._balanced(s, '{', '}')
        if seg:
            try:
                return json.loads(seg)
            except Exception:
                pass
        seg = self._balanced(s, '[', ']')
        if seg:
            try:
                return json.loads(seg)
            except Exception:
                pass
        try:
            i0 = s.find('{')
            i1 = s.rfind('}')
            if i0 != -1 and i1 != -1 and i1 > i0:
                return json.loads(s[i0:i1+1])
        except Exception:
            pass
        try:
            i0 = s.find('[')
            i1 = s.rfind(']')
            if i0 != -1 and i1 != -1 and i1 > i0:
                return json.loads(s[i0:i1+1])
        except Exception:
            pass
        return None

    def redact_headers(self, headers):
        if isinstance(headers, dict):
            out = {}
            for k, v in headers.items():
                lk = (k or "").lower()
                if lk in ("authorization", "cookie", "x-api-key"):
                    out[k] = "[redacted]"
                else:
                    out[k] = v
            return out
        return headers


class BurpUi(object):
    def __init__(self, extender):
        self.extender = extender
        self.root = JPanel(BorderLayout())
        self.tabs = JTabbedPane()
        self.chat_view = None
        self.input_field = None
        self.renderer = HtmlRenderer()
        self.api_key_field = None
        self.model_field = None
        self.prompt_area = None
        self.notebook_field = None
        self.rpm_field = None
        self.strict_json_cb = None
        self.auto_mode_cb = None
        self.auto_iters_field = None
        self.auto_adaptive_cb = None
        self.lc_mode_cb = None
        self.lc_base_field = None
        self.lc_depth_field = None
        self.lc_scope_cb = None
        self.lc_bodies_cb = None
        self.lc_limit_field = None
        self.modelio_area = None
        self.tool_results_area = None
        self.debug_area = None
        self.target_area = None
        self.target_prefix = None
        self.history_area = None
        self.history_query = None
        self.queue_area = None
        self.kill_checkbox = None
        
        self._build_tabs()
        self.root.add(self.tabs, BorderLayout.CENTER)

    def _build_tabs(self):
        self.tabs.addTab("Agent", self._build_agent_tab())
        self.tabs.addTab("Target", self._build_target_tab())
        self.tabs.addTab("HTTP History", self._build_history_tab())
        self.tabs.addTab("Queue", self._build_queue_tab())
        self.tabs.addTab("Settings", self._build_settings_tab())
        self.tabs.addTab("Model I/O", self._build_modelio_tab())
        self.tabs.addTab("Debug", self._build_debug_tab())
        self.tabs.addTab("Tool Results", self._build_toolresults_tab())

    def _build_agent_tab(self):
        panel = JPanel(BorderLayout())
        self.chat_view = JEditorPane()
        self.chat_view.setEditable(False)
        self.chat_view.setEditorKit(HTMLEditorKit())
        try:
            self.chat_view.setContentType("text/html")
        except Exception:
            pass
        self.chat_view.setText(self.renderer.to_html())
        sc = JScrollPane(self.chat_view)

        input_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(4, 4, 4, 4)
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.weightx = 1.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.input_field = JTextField()
        input_panel.add(self.input_field, gbc)
        gbc.gridx = 1
        gbc.weightx = 0
        send_btn = JButton("Send")
        save_btn = JButton("Save Chat")
        load_btn = JButton("Load Chat")

        class SendAction(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender._send_chat()

        send_btn.addActionListener(SendAction(self))
        input_panel.add(send_btn, gbc)
        gbc.gridx = 2
        class SaveChat(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender._quick_save_chat()
        save_btn.addActionListener(SaveChat(self))
        input_panel.add(save_btn, gbc)
        gbc.gridx = 3
        class LoadChat(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender._quick_load_chat()
        load_btn.addActionListener(LoadChat(self))
        input_panel.add(load_btn, gbc)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split.setResizeWeight(0.8)
        split.setTopComponent(sc)
        split.setBottomComponent(input_panel)
        panel.add(split, BorderLayout.CENTER)
        return panel

    def _build_target_tab(self):
        panel = JPanel(BorderLayout())
        self.target_area = JTextArea()
        self.target_area.setEditable(False)
        refresh = JButton("Refresh")
        search_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(4,4,4,4)
        gbc.gridx = 0
        gbc.gridy = 0
        search_panel.add(JLabel("Prefix"), gbc)
        gbc.gridx = 1
        self.target_prefix = JTextField()
        search_panel.add(self.target_prefix, gbc)
        gbc.gridx = 2
        do_search = JButton("Search")

        class Refresh(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender._refresh_target()

        refresh.addActionListener(Refresh(self))
        class DoSearch(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender._search_target()
        do_search.addActionListener(DoSearch(self))
        top = JPanel(BorderLayout())
        top.add(refresh, BorderLayout.WEST)
        top.add(search_panel, BorderLayout.CENTER)
        panel.add(top, BorderLayout.NORTH)
        panel.add(JScrollPane(self.target_area), BorderLayout.CENTER)
        return panel

    def _build_history_tab(self):
        panel = JPanel(BorderLayout())
        self.history_area = JTextArea()
        self.history_area.setEditable(False)
        search_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(4,4,4,4)
        gbc.gridx = 0
        gbc.gridy = 0
        search_panel.add(JLabel("Query"), gbc)
        gbc.gridx = 1
        self.history_query = JTextField()
        search_panel.add(self.history_query, gbc)
        gbc.gridx = 2
        search_btn = JButton("Search")
        class HistorySearch(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender._search_history()
        search_btn.addActionListener(HistorySearch(self))
        gbc.gridx = 3
        list_btn = JButton("List")
        class HistoryList(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender._list_history()
        list_btn.addActionListener(HistoryList(self))
        search_panel.add(search_btn, gbc)
        gbc.gridx = 4
        search_panel.add(list_btn, gbc)
        panel.add(search_panel, BorderLayout.NORTH)
        panel.add(JScrollPane(self.history_area), BorderLayout.CENTER)
        return panel

    def _build_queue_tab(self):
        panel = JPanel(BorderLayout())
        self.queue_area = JTextArea()
        self.queue_area.setEditable(False)
        top = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(4,4,4,4)
        gbc.gridx = 0
        gbc.gridy = 0
        approve = JButton("Approve Next")
        class Approve(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender._approve_next()
        approve.addActionListener(Approve(self))
        top.add(approve, gbc)
        gbc.gridx = 1
        reject = JButton("Reject Next")
        class Reject(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender._reject_next()
        reject.addActionListener(Reject(self))
        top.add(reject, gbc)
        gbc.gridx = 2
        send = JButton("Send Next")
        class SendNext(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender._send_next()
        send.addActionListener(SendNext(self))
        top.add(send, gbc)
        gbc.gridx = 3
        self.kill_checkbox = JCheckBox("Kill Switch")
        class KillToggle(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender.kill_switch = self.ui.kill_checkbox.isSelected()
        self.kill_checkbox.addActionListener(KillToggle(self))
        top.add(self.kill_checkbox, gbc)
        panel.add(top, BorderLayout.NORTH)
        panel.add(JScrollPane(self.queue_area), BorderLayout.CENTER)
        return panel

    def _build_modelio_tab(self):
        panel = JPanel(BorderLayout())
        self.modelio_area = JTextArea()
        self.modelio_area.setEditable(False)
        panel.add(JScrollPane(self.modelio_area), BorderLayout.CENTER)
        return panel

    def _build_debug_tab(self):
        panel = JPanel(BorderLayout())
        self.debug_area = JTextArea()
        self.debug_area.setEditable(False)
        panel.add(JScrollPane(self.debug_area), BorderLayout.CENTER)
        controls = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(4,4,4,4)
        gbc.gridx = 0
        gbc.gridy = 0
        clear_btn = JButton("Clear")
        class ClearDebug(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender._clear_debug()
        clear_btn.addActionListener(ClearDebug(self))
        controls.add(clear_btn, gbc)
        panel.add(controls, BorderLayout.SOUTH)
        return panel

    def _build_toolresults_tab(self):
        panel = JPanel(BorderLayout())
        self.tool_results_area = JTextArea()
        self.tool_results_area.setEditable(False)
        panel.add(JScrollPane(self.tool_results_area), BorderLayout.CENTER)
        controls = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(4,4,4,4)
        gbc.gridx = 0
        gbc.gridy = 0
        clear_btn = JButton("Clear")
        class ClearTR(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                try:
                    self.ui.extender.tool_results = []
                    self.ui.tool_results_area.setText("")
                except Exception:
                    pass
        clear_btn.addActionListener(ClearTR(self))
        controls.add(clear_btn, gbc)
        panel.add(controls, BorderLayout.SOUTH)
        return panel

    def _build_settings_tab(self):
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(4, 4, 4, 4)
        gbc.fill = GridBagConstraints.HORIZONTAL

        gbc.gridx = 0
        gbc.gridy = 0
        panel.add(JLabel("API Key"), gbc)
        gbc.gridx = 1
        self.api_key_field = JTextField(self.extender.store.get_api_key())
        panel.add(self.api_key_field, gbc)
        gbc.gridx = 2
        save_key = JButton("Save")

        class SaveKey(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender.store.set_api_key(self.ui.api_key_field.getText())
                JOptionPane.showMessageDialog(self.ui.root, "Saved")

        save_key.addActionListener(SaveKey(self))
        panel.add(save_key, gbc)

        gbc.gridx = 0
        gbc.gridy = 1
        panel.add(JLabel("Model"), gbc)
        gbc.gridx = 1
        self.model_field = JTextField(self.extender.store.get_model())
        panel.add(self.model_field, gbc)
        gbc.gridx = 2
        save_model = JButton("Save")

        class SaveModel(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender.store.set_model(self.ui.model_field.getText())
                JOptionPane.showMessageDialog(self.ui.root, "Saved")

        save_model.addActionListener(SaveModel(self))
        panel.add(save_model, gbc)

        gbc.gridx = 0
        gbc.gridy = 2
        panel.add(JLabel("System Prompt"), gbc)
        gbc.gridx = 1
        self.prompt_area = JTextArea(self.extender.store.get_system_prompt(), 5, 40)
        panel.add(JScrollPane(self.prompt_area), gbc)
        gbc.gridx = 2
        save_prompt = JButton("Save")

        class SavePrompt(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender.store.set_system_prompt(self.ui.prompt_area.getText())
                JOptionPane.showMessageDialog(self.ui.root, "Saved")

        save_prompt.addActionListener(SavePrompt(self))
        panel.add(save_prompt, gbc)

        gbc.gridx = 3
        reset_prompt = JButton("Reset")

        class ResetPrompt(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                try:
                    dflt = self.ui.extender.store._default_system_prompt()
                except Exception:
                    dflt = ""
                try:
                    self.ui.prompt_area.setText(dflt)
                except Exception:
                    pass
                self.ui.extender.store.set_system_prompt(dflt)
                JOptionPane.showMessageDialog(self.ui.root, "Reset")

        reset_prompt.addActionListener(ResetPrompt(self))
        panel.add(reset_prompt, gbc)

        gbc.gridx = 0
        gbc.gridy = 3
        panel.add(JLabel("Notebook Path"), gbc)
        gbc.gridx = 1
        self.notebook_field = JTextField(self.extender.store.get_notebook_path())
        panel.add(self.notebook_field, gbc)
        gbc.gridx = 2
        save_nb = JButton("Save")
        class SaveNB(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender.store.set_notebook_path(self.ui.notebook_field.getText())
                JOptionPane.showMessageDialog(self.ui.root, "Saved")
        save_nb.addActionListener(SaveNB(self))
        panel.add(save_nb, gbc)

        gbc.gridx = 0
        gbc.gridy = 4
        panel.add(JLabel("RPM Limit"), gbc)
        gbc.gridx = 1
        self.rpm_field = JTextField(str(self.extender.store.get_rpm_limit()))
        panel.add(self.rpm_field, gbc)
        gbc.gridx = 2
        save_rpm = JButton("Save")
        class SaveRPM(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender.store.set_rpm_limit(self.ui.rpm_field.getText())
                JOptionPane.showMessageDialog(self.ui.root, "Saved")
        save_rpm.addActionListener(SaveRPM(self))
        panel.add(save_rpm, gbc)

        gbc.gridx = 0
        gbc.gridy = 5
        panel.add(JLabel("Strict JSON Mode"), gbc)
        gbc.gridx = 1
        self.strict_json_cb = JCheckBox("Enabled", self.extender.store.get_strict_json_mode())
        panel.add(self.strict_json_cb, gbc)
        gbc.gridx = 2
        save_strict = JButton("Save")

        class SaveStrict(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                try:
                    self.ui.extender.store.set_strict_json_mode(self.ui.strict_json_cb.isSelected())
                except Exception:
                    self.ui.extender.store.set_strict_json_mode(False)
                JOptionPane.showMessageDialog(self.ui.root, "Saved")

        save_strict.addActionListener(SaveStrict(self))
        panel.add(save_strict, gbc)

        gbc.gridx = 0
        gbc.gridy = 6
        test_btn = JButton("Test OpenRouter")

        class TestOR(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender._test_openrouter()

        test_btn.addActionListener(TestOR(self))
        panel.add(test_btn, gbc)

        gbc.gridx = 1
        list_btn = JButton("List Models")

        class ListModels(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                self.ui.extender._list_models()

        list_btn.addActionListener(ListModels(self))
        panel.add(list_btn, gbc)

        gbc.gridx = 0
        gbc.gridy = 7
        panel.add(JLabel("Autonomous Mode"), gbc)
        gbc.gridx = 1
        self.auto_mode_cb = JCheckBox("Enabled", self.extender.store.get_auto_mode())
        panel.add(self.auto_mode_cb, gbc)
        gbc.gridx = 2
        save_auto_mode = JButton("Save")

        class SaveAutoMode(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                try:
                    self.ui.extender.store.set_auto_mode(self.ui.auto_mode_cb.isSelected())
                except Exception:
                    self.ui.extender.store.set_auto_mode(False)
                JOptionPane.showMessageDialog(self.ui.root, "Saved")

        save_auto_mode.addActionListener(SaveAutoMode(self))
        panel.add(save_auto_mode, gbc)

        gbc.gridx = 0
        gbc.gridy = 8
        panel.add(JLabel("Auto Iterations"), gbc)
        gbc.gridx = 1
        self.auto_iters_field = JTextField(str(self.extender.store.get_auto_iterations()))
        panel.add(self.auto_iters_field, gbc)
        gbc.gridx = 2
        save_auto_iters = JButton("Save")

        class SaveAutoIters(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                try:
                    self.ui.extender.store.set_auto_iterations(self.ui.auto_iters_field.getText())
                except Exception:
                    self.ui.extender.store.set_auto_iterations(10)
                JOptionPane.showMessageDialog(self.ui.root, "Saved")

        save_auto_iters.addActionListener(SaveAutoIters(self))
        panel.add(save_auto_iters, gbc)

        gbc.gridx = 0
        gbc.gridy = 9
        panel.add(JLabel("Adaptive Control"), gbc)
        gbc.gridx = 1
        self.auto_adaptive_cb = JCheckBox("Model decides when to stop", self.extender.store.get_auto_adaptive())
        panel.add(self.auto_adaptive_cb, gbc)
        gbc.gridx = 2
        save_auto_adaptive = JButton("Save")

        class SaveAutoAdaptive(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                try:
                    self.ui.extender.store.set_auto_adaptive(self.ui.auto_adaptive_cb.isSelected())
                except Exception:
                    self.ui.extender.store.set_auto_adaptive(True)
                JOptionPane.showMessageDialog(self.ui.root, "Saved")

        save_auto_adaptive.addActionListener(SaveAutoAdaptive(self))
        panel.add(save_auto_adaptive, gbc)

        gbc.gridx = 0
        gbc.gridy = 10
        panel.add(JLabel("Large Context Mode"), gbc)
        gbc.gridx = 1
        self.lc_mode_cb = JCheckBox("Enabled", self.extender.store.get_large_context_mode())
        panel.add(self.lc_mode_cb, gbc)
        gbc.gridx = 2
        lc_mode_save = JButton("Save")

        class SaveLCMode(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                try:
                    self.ui.extender.store.set_large_context_mode(self.ui.lc_mode_cb.isSelected())
                except Exception:
                    self.ui.extender.store.set_large_context_mode(False)
                JOptionPane.showMessageDialog(self.ui.root, "Saved")

        lc_mode_save.addActionListener(SaveLCMode(self))
        panel.add(lc_mode_save, gbc)

        gbc.gridx = 0
        gbc.gridy = 11
        panel.add(JLabel("LC Base URL"), gbc)
        gbc.gridx = 1
        self.lc_base_field = JTextField(self.extender.store.get_large_context_base_url())
        panel.add(self.lc_base_field, gbc)
        gbc.gridx = 2
        lc_base_save = JButton("Save")

        class SaveLCBase(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                try:
                    self.ui.extender.store.set_large_context_base_url(self.ui.lc_base_field.getText())
                except Exception:
                    self.ui.extender.store.set_large_context_base_url("")
                JOptionPane.showMessageDialog(self.ui.root, "Saved")

        lc_base_save.addActionListener(SaveLCBase(self))
        panel.add(lc_base_save, gbc)

        gbc.gridx = 0
        gbc.gridy = 12
        panel.add(JLabel("LC Max Depth"), gbc)
        gbc.gridx = 1
        self.lc_depth_field = JTextField(str(self.extender.store.get_large_context_max_depth()))
        panel.add(self.lc_depth_field, gbc)
        gbc.gridx = 2
        lc_depth_save = JButton("Save")

        class SaveLCDepth(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                try:
                    self.ui.extender.store.set_large_context_max_depth(self.ui.lc_depth_field.getText())
                except Exception:
                    self.ui.extender.store.set_large_context_max_depth(-1)
                JOptionPane.showMessageDialog(self.ui.root, "Saved")

        lc_depth_save.addActionListener(SaveLCDepth(self))
        panel.add(lc_depth_save, gbc)

        gbc.gridx = 0
        gbc.gridy = 13
        panel.add(JLabel("LC Respect Scope"), gbc)
        gbc.gridx = 1
        self.lc_scope_cb = JCheckBox("Enabled", self.extender.store.get_large_context_respect_scope())
        panel.add(self.lc_scope_cb, gbc)
        gbc.gridx = 2
        lc_scope_save = JButton("Save")

        class SaveLCScope(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                try:
                    self.ui.extender.store.set_large_context_respect_scope(self.ui.lc_scope_cb.isSelected())
                except Exception:
                    self.ui.extender.store.set_large_context_respect_scope(True)
                JOptionPane.showMessageDialog(self.ui.root, "Saved")

        lc_scope_save.addActionListener(SaveLCScope(self))
        panel.add(lc_scope_save, gbc)

        gbc.gridx = 0
        gbc.gridy = 14
        panel.add(JLabel("LC Include Bodies"), gbc)
        gbc.gridx = 1
        self.lc_bodies_cb = JCheckBox("Enabled", self.extender.store.get_large_context_include_bodies())
        panel.add(self.lc_bodies_cb, gbc)
        gbc.gridx = 2
        lc_bodies_save = JButton("Save")

        class SaveLCBodies(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                try:
                    self.ui.extender.store.set_large_context_include_bodies(self.ui.lc_bodies_cb.isSelected())
                except Exception:
                    self.ui.extender.store.set_large_context_include_bodies(True)
                JOptionPane.showMessageDialog(self.ui.root, "Saved")

        lc_bodies_save.addActionListener(SaveLCBodies(self))
        panel.add(lc_bodies_save, gbc)

        gbc.gridx = 0
        gbc.gridy = 15
        panel.add(JLabel("LC Entry Limit"), gbc)
        gbc.gridx = 1
        self.lc_limit_field = JTextField(str(self.extender.store.get_large_context_limit()))
        panel.add(self.lc_limit_field, gbc)
        gbc.gridx = 2
        lc_limit_save = JButton("Save")

        class SaveLCLimit(ActionListener):
            def __init__(self, ui):
                self.ui = ui
            def actionPerformed(self, e):
                try:
                    self.ui.extender.store.set_large_context_limit(self.ui.lc_limit_field.getText())
                except Exception:
                    self.ui.extender.store.set_large_context_limit(-1)
                JOptionPane.showMessageDialog(self.ui.root, "Saved")

        lc_limit_save.addActionListener(SaveLCLimit(self))
        panel.add(lc_limit_save, gbc)
        return panel


class BurpExtender(IBurpExtender, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp AI Agent Clean")
        self.logger = Logger(callbacks)
        self.store = SettingsStore(self.logger)
        self.client = OpenRouterClient(callbacks, self.logger)
        self.target = TargetHelper(callbacks, self.logger)
        self.history = HttpHistoryHelper(callbacks, self.logger)
        self.json = JsonUtils()
        self.queue = []
        self.kill_switch = False
        self.send_times = []
        self.tool_results = []
        self.large_context_buffer = ""
        self.ui = BurpUi(self)
        try:
            self.client.set_debug_logger(self._log_debug)
        except Exception:
            pass
        try:
            self._log_debug("debug logger initialized")
        except Exception:
            pass
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)

    def getTabCaption(self):
        return "AI Agent"

    def getUiComponent(self):
        return self.ui.root

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        return















    def _refresh_target(self):
        urls = self.target.list_urls()
        self.ui.target_area.setText("\n".join(urls))

    def _search_target(self):
        pref = self.ui.target_prefix.getText() or ""
        urls = [u for u in self.target.list_urls() if pref and u.startswith(pref)] if pref else self.target.list_urls()
        self.ui.target_area.setText("\n".join(urls))

    def _test_openrouter(self):
        api_key = self.ui.api_key_field.getText() or self.store.get_api_key()
        model = self.ui.model_field.getText() or self.store.get_model()
        prompt = "Ping. Respond with OK."
        try:
            self._log_debug("test_openrouter start model=" + str(model))
        except Exception:
            pass
        def _run():
            try:
                res = self.client.call(api_key, model, self.store.get_system_prompt(), prompt)
            except Exception as e:
                def _err():
                    try:
                        self.ui.modelio_area.setText("Test error: " + str(e))
                        try:
                            self._log_debug("test_openrouter error: " + str(e))
                            self._log_debug(traceback.format_exc())
                        except Exception:
                            pass
                    except Exception:
                        pass
                try:
                    SwingUtilities.invokeLater(_err)
                except Exception:
                    _err()
                return
            def _upd():
                try:
                    dbg = res.get("debug") or ""
                    raw = res.get("raw") or ""
                    self.ui.modelio_area.setText("Status: {}\n".format(res.get("status")) + (dbg + ("\n\n" if dbg and raw else "")) + raw)
                    try:
                        self._log_debug("test_openrouter status=" + str(res.get("status")))
                        if dbg:
                            self._log_debug(dbg)
                        if raw:
                            self._log_debug(raw)
                    except Exception:
                        pass
                except Exception:
                    pass
            try:
                SwingUtilities.invokeLater(_upd)
            except Exception:
                _upd()
        try:
            threading.Thread(target=_run).start()
        except Exception as e:
            try:
                self.ui.modelio_area.setText("Thread error: " + str(e))
            except Exception:
                pass

    def _list_models(self):
        api_key = self.ui.api_key_field.getText() or self.store.get_api_key()
        try:
            self._log_debug("list_models start")
        except Exception:
            pass
        def _run():
            try:
                res = self.client.list_models(api_key)
            except Exception as e:
                def _err():
                    try:
                        self.ui.modelio_area.setText("Models error: " + str(e))
                        try:
                            self._log_debug("list_models error: " + str(e))
                            self._log_debug(traceback.format_exc())
                        except Exception:
                            pass
                    except Exception:
                        pass
                try:
                    SwingUtilities.invokeLater(_err)
                except Exception:
                    _err()
                return
            def _upd():
                try:
                    dbg = res.get("debug") or ""
                    raw = res.get("raw") or ""
                    self.ui.modelio_area.setText("Status: {}\n".format(res.get("status")) + (dbg + ("\n\n" if dbg and raw else "")) + raw)
                    try:
                        self._log_debug("list_models status=" + str(res.get("status")))
                        if dbg:
                            self._log_debug(dbg)
                        if raw:
                            self._log_debug(raw)
                    except Exception:
                        pass
                except Exception:
                    pass
            try:
                SwingUtilities.invokeLater(_upd)
            except Exception:
                _upd()
        try:
            threading.Thread(target=_run).start()
        except Exception as e:
            try:
                self.ui.modelio_area.setText("Thread error: " + str(e))
            except Exception:
                pass



    def _list_history(self):
        items = self.history.list()
        lines = ["{} {} [{} {}]".format(it.get("method"), it.get("url"), it.get("status"), it.get("mime")) for it in items]
        self.ui.history_area.setText("\n".join(lines))

    def _search_history(self):
        q = self.ui.history_query.getText()
        items = self.history.search(q)
        lines = ["{} {}".format(it.get("method"), it.get("url")) for it in items]
        self.ui.history_area.setText("\n".join(lines))



    def _log_debug(self, text):
        msg = "[" + time.strftime("%H:%M:%S") + "] " + str(text)
        if self.logger:
            self.logger.debug(msg)
        def _upd():
            try:
                if hasattr(self, 'ui') and self.ui and self.ui.debug_area:
                    self.ui.debug_area.append(msg + "\n")
                    try:
                        self.ui.debug_area.setCaretPosition(self.ui.debug_area.getDocument().getLength())
                    except Exception:
                        pass
            except Exception:
                pass
        try:
            SwingUtilities.invokeLater(_upd)
        except Exception:
            _upd()

    def _append_tool_result_obj(self, tool, payload):
        try:
            entry = {"tool": tool, "timestamp": time.strftime("%H:%M:%S"), "payload": payload}
            self.tool_results.append(entry)
            if len(self.tool_results) > 50:
                self.tool_results = self.tool_results[-50:]
            try:
                txt = "\n\n".join([json.dumps(x, indent=2) for x in self.tool_results[-10:]])
                self.ui.tool_results_area.setText(txt)
                try:
                    self.ui.tool_results_area.setCaretPosition(self.ui.tool_results_area.getDocument().getLength())
                except Exception:
                    pass
            except Exception:
                pass
        except Exception:
            pass

    def _clear_debug(self):
        try:
            self.ui.debug_area.setText("")
        except Exception:
            pass

    def _append_chat(self, role, text):
        def _upd():
            try:
                self.ui.renderer.add(role, text)
                self.ui.chat_view.setText(self.ui.renderer.to_html())
                try:
                    self.ui.chat_view.setCaretPosition(self.ui.chat_view.getDocument().getLength())
                except Exception:
                    try:
                        self.ui.chat_view.setCaretPosition(len(self.ui.chat_view.getText()))
                    except Exception:
                        pass
                try:
                    self.ui.chat_view.revalidate()
                    self.ui.chat_view.repaint()
                except Exception:
                    pass
            except Exception:
                pass
        try:
            if hasattr(SwingUtilities, 'isEventDispatchThread') and not SwingUtilities.isEventDispatchThread():
                SwingUtilities.invokeLater(_upd)
            else:
                _upd()
        except Exception:
            _upd()

    def _send_chat(self):
        user_text = self.ui.input_field.getText()
        if not user_text or not user_text.strip():
            return
        self._append_chat("user", user_text)
        api_key = self.ui.api_key_field.getText() or self.store.get_api_key()
        model = self.ui.model_field.getText() or self.store.get_model()
        prompt = self.ui.prompt_area.getText() or self.store.get_system_prompt()
        try:
            if self.store.get_strict_json_mode() and not self.store.get_large_context_mode():
                prompt = (prompt or "") + "\nReturn one strict JSON object only."
        except Exception:
            pass
        try:
            if self.store.get_large_context_mode():
                try:
                    self._ensure_large_context_pack()
                    if self.large_context_buffer:
                        user_text = (user_text or "") + "\n\nCONTEXT_PACK:\n" + self.large_context_buffer
                except Exception:
                    pass
        except Exception:
            pass
        try:
            if self.store.get_large_context_mode():
                prompt = (prompt or "") + (
                    "\nLarge Context Reasoning:\n"
                    "- Chain-of-thought is allowed without any constraints.\n"
                    "- Prefer minimal tool calls; rely on the provided context.\n"
                    "- When using tools, include a JSON block with tool_calls; otherwise reply directly.\n"
                )
        except Exception:
            pass
        try:
            ctx = []
            try:
                ctx = self.tool_results[-5:]
            except Exception:
                ctx = []
            if ctx:
                try:
                    user_text = (user_text or "") + "\n\nTOOL_RESULTS:\n" + json.dumps(ctx)
                except Exception:
                    pass
        except Exception:
            pass
        try:
            self._log_debug("send_chat start model=" + str(model) + ", system_len=" + str(len(prompt or "")) + ", user_len=" + str(len(user_text or "")))
        except Exception:
            pass
        try:
            if self.store.get_auto_mode():
                try:
                    n = int(self.store.get_auto_iterations())
                except Exception:
                    n = 10
                if n >= 2:
                    def _autorun():
                        try:
                            self._run_autonomous_chat(api_key, model, prompt, user_text, n)
                        except Exception:
                            pass
                    try:
                        threading.Thread(target=_autorun).start()
                    except Exception:
                        _autorun()
                    return
        except Exception:
            pass
        def _run():
            try:
                res = self.client.call(api_key, model, prompt, user_text)
            except Exception as e:
                def _err():
                    try:
                        self.ui.modelio_area.setText("Error: " + str(e))
                        self._append_chat("assistant", "error: " + str(e))
                        try:
                            self._log_debug("send_chat error: " + str(e))
                            self._log_debug(traceback.format_exc())
                        except Exception:
                            pass
                    except Exception:
                        pass
                try:
                    SwingUtilities.invokeLater(_err)
                except Exception:
                    _err()
                return
            def _upd():
                try:
                    dbg = res.get("debug") or ""
                    raw = res.get("raw") or ""
                    if dbg or raw:
                        self.ui.modelio_area.setText((dbg + ("\n\n" if dbg and raw else "")) + raw)
                        try:
                            self._log_debug("send_chat status=" + str(res.get("status")))
                            if dbg:
                                self._log_debug(dbg)
                            if raw:
                                self._log_debug(raw)
                        except Exception:
                            pass
                    content = res.get("content") or ""
                    self._append_chat("assistant", content)
                    obj = self.json.extract_json_any(content)
                    if self.store.get_strict_json_mode() and obj is None:
                        try:
                            self.ui.modelio_area.setText("Strict JSON mode: no JSON detected.")
                            self._log_debug("strict_json: no JSON in assistant content")
                        except Exception:
                            pass
                    if isinstance(obj, list):
                        try:
                            self._execute_tool_calls(obj)
                        except Exception:
                            pass
                    elif isinstance(obj, dict):
                        try:
                            r = obj.get("reply") or ""
                            if r:
                                self._append_chat("assistant", r)
                        except Exception:
                            pass
                        try:
                            tc = obj.get("tool_calls")
                            if tc:
                                self._execute_tool_calls(tc)
                        except Exception:
                            pass
                        try:
                            th = obj.get("thinking") or obj.get("thinking_brief")
                            if th:
                                self._log_debug("thinking: " + str(th))
                        except Exception:
                            pass
                        try:
                            notes = obj.get("notes")
                            if isinstance(notes, list) and notes:
                                self._append_notebook("\n".join([str(x) for x in notes]))
                                self._append_chat("assistant", "notes appended")
                        except Exception:
                            pass
                except Exception as e2:
                    try:
                        self.ui.modelio_area.setText("Update error: " + str(e2))
                        try:
                            self._log_debug("send_chat update error: " + str(e2))
                            self._log_debug(traceback.format_exc())
                        except Exception:
                            pass
                    except Exception:
                        pass
            try:
                SwingUtilities.invokeLater(_upd)
            except Exception:
                _upd()
        try:
            threading.Thread(target=_run).start()
        except Exception as e:
            try:
                self.ui.modelio_area.setText("Thread error: " + str(e))
                try:
                    self._log_debug("send_chat thread error: " + str(e))
                    self._log_debug(traceback.format_exc())
                except Exception:
                    pass
            except Exception:
                pass

    def _execute_tool_calls(self, calls):
        acc_http = []
        acc_target = []
        for c in calls:
            try:
                tool = c.get("tool")
                args = c.get("args") or {}
                if tool == "list_target_sitemap":
                    pref = args.get("path_prefix") or ""
                    try:
                        md = int(args.get("max_depth", -1))
                    except Exception:
                        md = -1
                    rs = True
                    try:
                        rs = bool(args.get("respect_scope", True))
                    except Exception:
                        rs = True
                    try:
                        lim = int(args.get("limit", 200))
                    except Exception:
                        lim = 200
                    hsub = args.get("host_sub") or None
                    urls = self.target.list_urls_filtered(path_prefix=(pref or None), max_depth=md, respect_scope=rs, limit=lim, host_sub=hsub)
                    self._append_chat("assistant", "list_target_sitemap found {} entries".format(len(urls)))
                    self._append_tool_result_obj("list_target_sitemap", {"items": urls})
                elif tool == "search_target":
                    q = (args.get("query") or "").lower()
                    pref = args.get("path_prefix") or ""
                    try:
                        md = int(args.get("max_depth", -1))
                    except Exception:
                        md = -1
                    rs = True
                    try:
                        rs = bool(args.get("respect_scope", True))
                    except Exception:
                        rs = True
                    try:
                        lim = int(args.get("limit", 200))
                    except Exception:
                        lim = 200
                    hsub = args.get("host_sub") or None
                    urls = self.target.list_urls_filtered(path_prefix=(pref or None), max_depth=md, respect_scope=rs, limit=lim, host_sub=hsub)
                    hits = [u for u in urls if q in u.lower()][:lim]
                    if not hits and rs:
                        urls2 = self.target.list_urls_filtered(path_prefix=(pref or None), max_depth=md, respect_scope=False, limit=lim, host_sub=hsub)
                        hits = [u for u in urls2 if q in u.lower()][:lim]
                        self._append_chat("assistant", "search_target found {} hits (scope: false)".format(len(hits)))
                    else:
                        self._append_chat("assistant", "search_target found {} hits (scope: {})".format(len(hits), rs))
                    if hits:
                        self._append_chat("assistant", "search_target hits:\n" + "\n".join(hits))
                    self._append_tool_result_obj("search_target", {"items": hits})
                    try:
                        acc_target.extend(hits)
                    except Exception:
                        pass
                elif tool == "get_target_entry":
                    val = args.get("value")
                    if val:
                        self._append_chat("assistant", "target entry: " + val)
                elif tool == "search_http":
                    q = args.get("query")
                    try:
                        lim = int(args.get("limit", 200))
                    except Exception:
                        lim = 200
                    rs = True
                    try:
                        rs = bool(args.get("respect_scope", True))
                    except Exception:
                        rs = True
                    ib = False; ir = False; ih = False; rgx = False
                    try:
                        ib = bool(args.get("in_body", False))
                    except Exception:
                        ib = False
                    try:
                        ir = bool(args.get("in_req", False))
                    except Exception:
                        ir = False
                    try:
                        ih = bool(args.get("in_headers", False))
                    except Exception:
                        ih = False
                    try:
                        rgx = bool(args.get("regex", False))
                    except Exception:
                        rgx = False
                    try:
                        smin = int(args.get("status_min", 0))
                    except Exception:
                        smin = 0
                    try:
                        smax = int(args.get("status_max", 999))
                    except Exception:
                        smax = 999
                    msub = str(args.get("mime_sub", ""))
                    hsub = str(args.get("host_sub", ""))
                    items = self.history.search(q, limit=lim, respect_scope=rs, in_body=ib, in_req=ir, in_headers=ih, regex=rgx, status_min=smin, status_max=smax, mime_sub=msub, host_sub=hsub)
                    if not items and rs:
                        items = self.history.search(q, limit=lim, respect_scope=False, in_body=ib, in_req=ir, in_headers=ih, regex=rgx, status_min=smin, status_max=smax, mime_sub=msub, host_sub=hsub)
                        self._append_chat("assistant", "search_http found {} items (scope: false)".format(len(items)))
                    else:
                        self._append_chat("assistant", "search_http found {} items (scope: {})".format(len(items), rs))
                    if items:
                        lines = []
                        for it in items[:min(len(items), lim)]:
                            m = it.get("match") or ""
                            idx = it.get("index")
                            head = "#{} {} {}".format(idx, it.get("method"), it.get("url")) if idx is not None else "{} {}".format(it.get("method"), it.get("url"))
                            if m:
                                lines.append(head + " | " + m[:160])
                            else:
                                lines.append(head)
                        self._append_chat("assistant", "search_http:\n" + "\n".join(lines))
                    self._append_tool_result_obj("search_http", {"items": items})
                    try:
                        acc_http.extend(items)
                    except Exception:
                        pass
                elif tool == "list_http_sitemap":
                    base = args.get("base_url") or ""
                    host = args.get("host") or None
                    pref = args.get("path_prefix") or None
                    try:
                        md = int(args.get("max_depth", -1))
                    except Exception:
                        md = -1
                    rs = True
                    try:
                        rs = bool(args.get("respect_scope", True))
                    except Exception:
                        rs = True
                    try:
                        lim = int(args.get("limit", 200))
                    except Exception:
                        lim = 200
                    try:
                        if base:
                            try:
                                u = URL(base)
                                host = host or (u.getHost() or None)
                                pref = pref or (u.getPath() or None)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    items = self.history.list_sitemap(host=host, path_prefix=pref, max_depth=md, respect_scope=rs, limit=lim)
                    if not items and rs:
                        items = self.history.list_sitemap(host=host, path_prefix=pref, max_depth=md, respect_scope=False, limit=lim)
                        self._append_chat("assistant", "list_http_sitemap found {} entries (scope: false)".format(len(items)))
                    else:
                        self._append_chat("assistant", "list_http_sitemap found {} entries (scope: {})".format(len(items), rs))
                    self._append_tool_result_obj("list_http_sitemap", {"items": items})
                elif tool == "get_http_body_by_url":
                    urls = args.get("urls")
                    if isinstance(urls, list) and urls:
                        out_items = []
                        for u in urls:
                            body = self.history.get_body_by_url(str(u), offset=int(args.get("offset", 0)), limit=int(args.get("limit", -1)))
                            if body is not None:
                                out_items.append({"url": str(u), "length": len(body), "body": body})
                        self._append_chat("assistant", "get_http_body_by_url fetched {} bodies".format(len(out_items)))
                        self._append_tool_result_obj("get_http_body_by_url", {"items": out_items})
                    else:
                        u = args.get("url") or ""
                        body = self.history.get_body_by_url(str(u), offset=int(args.get("offset", 0)), limit=int(args.get("limit", -1)))
                        if body is None:
                            self._append_chat("assistant", "http body unavailable for url")
                        else:
                            self._append_chat("assistant", "http body bytes=" + str(len(body)))
                            self._append_tool_result_obj("get_http_body_by_url", {"url": str(u), "length": len(body), "body": body})
                elif tool == "build_context_pack":
                    base = args.get("base_url") or self.store.get_large_context_base_url()
                    try:
                        self.store.set_large_context_base_url(base)
                    except Exception:
                        pass
                    try:
                        md = int(args.get("max_depth", self.store.get_large_context_max_depth()))
                        rs = bool(args.get("respect_scope", self.store.get_large_context_respect_scope()))
                        inc = bool(args.get("include_bodies", self.store.get_large_context_include_bodies()))
                        lim = int(args.get("limit", self.store.get_large_context_limit()))
                        self.store.set_large_context_max_depth(md)
                        self.store.set_large_context_respect_scope(rs)
                        self.store.set_large_context_include_bodies(inc)
                        self.store.set_large_context_limit(lim)
                    except Exception:
                        pass
                    try:
                        self._ensure_large_context_pack()
                        self._append_chat("assistant", "context pack built length=" + str(len(self.large_context_buffer)))
                        self._append_tool_result_obj("build_context_pack", {"length": len(self.large_context_buffer)})
                    except Exception as e:
                        self._append_chat("assistant", "context pack error: " + str(e))
                elif tool == "get_context_pack":
                    try:
                        buf = self.large_context_buffer or ""
                        self._append_tool_result_obj("get_context_pack", {"length": len(buf), "content": buf})
                        self._append_chat("assistant", "context pack length=" + str(len(buf)))
                    except Exception:
                        self._append_chat("assistant", "context pack unavailable")
                elif tool == "clear_context_pack":
                    try:
                        self.large_context_buffer = ""
                        self._append_chat("assistant", "context pack cleared")
                        self._append_tool_result_obj("clear_context_pack", {"ok": True})
                    except Exception:
                        pass
                elif tool == "get_http_entry":
                    idx = int(args.get("index", -1))
                    info = self.history.get_entry(idx)
                    if info:
                        self._append_chat("assistant", "http entry {}: {} {}".format(idx, info.get("method"), info.get("url")))
                        self._append_tool_result_obj("get_http_entry", {"index": idx, "entry": info})
                elif tool == "get_http_body":
                    idx = int(args.get("index", -1))
                    try:
                        off = int(args.get("offset", 0))
                    except Exception:
                        off = 0
                    try:
                        lim = int(args.get("limit", -1))
                    except Exception:
                        lim = -1
                    body = self.history.get_body(idx, offset=off, limit=lim)
                    if body is None:
                        self._append_chat("assistant", "http body unavailable")
                    else:
                        self._append_chat("assistant", "http body bytes=" + str(len(body)))
                        self._append_tool_result_obj("get_http_body", {"index": idx, "offset": off, "limit": lim, "length": len(body), "body": body})
                elif tool == "propose_request":
                    req = {
                        "method": args.get("method", "GET"),
                        "url": args.get("url", ""),
                        "headers": args.get("headers") or {},
                        "body": args.get("body") or "",
                        "rationale": args.get("rationale") or "",
                        "approved": False,
                    }
                    self.queue.append(req)
                    self._refresh_queue_view()
                    self._append_chat("assistant", "proposed request queued: {} {}".format(req["method"], req["url"]))
                    self._append_tool_result_obj("propose_request", req)
                elif tool == "send_request":
                    if self.kill_switch:
                        self._append_chat("assistant", "kill switch enabled; not sending")
                        continue
                    req = {
                        "method": args.get("method", "GET"),
                        "url": args.get("url", ""),
                        "headers": args.get("headers") or {},
                        "body": args.get("body") or "",
                        "approved": True,
                    }
                    try:
                        self._append_tool_result_obj("send_request", req)
                    except Exception:
                        pass
                    try:
                        self._dispatch_request(req)
                        self._append_chat("assistant", "sent: {} {}".format(req["method"], req["url"]))
                    except Exception:
                        try:
                            self.queue.append(req)
                            self._refresh_queue_view()
                            self._append_chat("assistant", "queued for send: {} {}".format(req["method"], req["url"]))
                        except Exception:
                            pass
                elif tool in ("note", "append_notebook"):
                    text = args.get("text") or ""
                    self._append_notebook(text)
                    self._append_chat("assistant", "notebook appended")
                    self._append_tool_result_obj("note", {"text": text})
            except Exception as e:
                self._append_chat("assistant", "tool error: " + str(e))
        try:
            if acc_http or acc_target:
                c_ht = len(acc_http)
                c_t = len(acc_target)
                lines = []
                if c_ht:
                    try:
                        uniq = []
                        seen = set()
                        for it in acc_http:
                            u = it.get("url")
                            if u and u not in seen:
                                seen.add(u)
                                m = it.get("match") or ""
                                if m:
                                    uniq.append("{} | {}".format(u, m[:160]))
                                else:
                                    uniq.append(u)
                            if len(uniq) >= 5:
                                break
                        lines.append("HTTP: {} items; sample:\n{}".format(c_ht, "\n".join(uniq)))
                    except Exception:
                        lines.append("HTTP: {} items".format(c_ht))
                if c_t:
                    try:
                        uniqt = []
                        seen2 = set()
                        for u in acc_target:
                            if u and u not in seen2:
                                seen2.add(u)
                                uniqt.append(u)
                            if len(uniqt) >= 5:
                                break
                        lines.append("Target: {} URLs; sample:\n{}".format(c_t, "\n".join(uniqt)))
                    except Exception:
                        lines.append("Target: {} URLs".format(c_t))
                self._append_chat("assistant", "Summary:\n" + "\n".join(lines))
                try:
                    if not self.store.get_auto_mode():
                        self._auto_followup_summary()
                except Exception:
                    pass
        except Exception:
            pass

    def _auto_followup_summary(self):
        try:
            api_key = self.ui.api_key_field.getText() or self.store.get_api_key()
            model = self.ui.model_field.getText() or self.store.get_model()
            prompt = self.ui.prompt_area.getText() or self.store.get_system_prompt()
            try:
                if self.store.get_strict_json_mode() and not self.store.get_large_context_mode():
                    prompt = (prompt or "") + "\nReturn one strict JSON object only."
            except Exception:
                pass
            ctx = []
            try:
                ctx = self.tool_results[-50:]
            except Exception:
                ctx = []
            if not ctx:
                return
            try:
                user_text = "Final summary of findings with URLs and snippets.\n\nTOOL_RESULTS:\n" + json.dumps(ctx)
            except Exception:
                return
            def _run2():
                try:
                    res = self.client.call(api_key, model, prompt, user_text)
                except Exception as e:
                    def _err2():
                        try:
                            self.ui.modelio_area.setText("Error: " + str(e))
                            self._append_chat("assistant", "error: " + str(e))
                        except Exception:
                            pass
                    try:
                        SwingUtilities.invokeLater(_err2)
                    except Exception:
                        _err2()
                    return
                def _upd2():
                    try:
                        content = res.get("content") or ""
                        obj = self.json.extract_json_any(content)
                        if isinstance(obj, dict):
                            try:
                                r = obj.get("reply") or obj.get("summary") or ""
                                if r:
                                    self._append_chat("assistant", r)
                            except Exception:
                                pass
                        elif isinstance(obj, list):
                            pass
                        else:
                            if content:
                                self._append_chat("assistant", content)
                    except Exception as e2:
                        try:
                            self.ui.modelio_area.setText("Update error: " + str(e2))
                        except Exception:
                            pass
                try:
                    SwingUtilities.invokeLater(_upd2)
                except Exception:
                    _upd2()
            try:
                threading.Thread(target=_run2).start()
            except Exception:
                pass
        except Exception:
            pass

    def _run_autonomous_chat(self, api_key, model, prompt, user_text, n):
        try:
            try:
                if self.store.get_strict_json_mode() and not self.store.get_large_context_mode():
                    prompt = (prompt or "") + "\nReturn one strict JSON object only."
            except Exception:
                pass
            has_final = False
            adaptive = False
            try:
                adaptive = bool(self.store.get_auto_adaptive())
            except Exception:
                adaptive = True
            for i in range(int(n)):
                ut = user_text
                try:
                    ctx = []
                    try:
                        ctx = self.tool_results[-10:]
                    except Exception:
                        ctx = []
                    if ctx:
                        try:
                            ut = (ut or "") + "\n\nTOOL_RESULTS:\n" + json.dumps(ctx)
                        except Exception:
                            pass
                    ut = (ut or "") + "\n\nIteration {}/{}: You may include short thinking segments (chain-of-thought allowed). Then return a JSON block with next tool_calls. Include {continue:boolean|next:boolean, reason_brief:string, confidence:number}. If final, include {reply} and no tool_calls.".format(i+1, n)
                except Exception:
                    pass
                try:
                    res = self.client.call(api_key, model, prompt, ut)
                except Exception as e:
                    try:
                        self.ui.modelio_area.setText("Error: " + str(e))
                    except Exception:
                        pass
                    break
                try:
                    dbg = res.get("debug") or ""
                    raw = res.get("raw") or ""
                    if dbg or raw:
                        self.ui.modelio_area.setText((dbg + ("\n\n" if dbg and raw else "")) + raw)
                except Exception:
                    pass
                try:
                    content = res.get("content") or ""
                    obj = self.json.extract_json_any(content)
                except Exception:
                    obj = None
                if isinstance(obj, list):
                    try:
                        self._execute_tool_calls(obj)
                    except Exception:
                        pass
                elif isinstance(obj, dict):
                    try:
                        tc = obj.get("tool_calls")
                        if tc:
                            self._execute_tool_calls(tc)
                    except Exception:
                        pass
                    try:
                        r = obj.get("reply") or ""
                        if r:
                            self._append_chat("assistant", r)
                            has_final = True
                    except Exception:
                        pass
                    try:
                        if adaptive:
                            cont = obj.get("continue")
                            if cont is None:
                                cont = obj.get("next")
                            if isinstance(cont, bool) and not cont:
                                break
                            if cont is None and not tc and not r:
                                break
                    except Exception:
                        pass
                else:
                    pass
            try:
                if not has_final:
                    self._auto_followup_summary()
            except Exception:
                pass
        except Exception:
            pass

    def _ensure_large_context_pack(self):
        try:
            base = self.store.get_large_context_base_url()
            if not base:
                return
            try:
                md = int(self.store.get_large_context_max_depth())
            except Exception:
                md = -1
            rs = True
            try:
                rs = bool(self.store.get_large_context_respect_scope())
            except Exception:
                rs = True
            inc = True
            try:
                inc = bool(self.store.get_large_context_include_bodies())
            except Exception:
                inc = True
            try:
                lim = int(self.store.get_large_context_limit())
            except Exception:
                lim = -1
            try:
                u = URL(base)
                host = u.getHost() or None
                pref = u.getPath() or None
            except Exception:
                host = None
                pref = None
            items = self.history.list_sitemap(host=host, path_prefix=pref, max_depth=md, respect_scope=rs, limit=(lim if lim and lim>0 else 1000000))
            lines = []
            for it in items:
                try:
                    head = "=== {} {} {} status={} mime={} depth={} ===\n".format(it.get("index"), it.get("method"), it.get("url"), it.get("status"), it.get("mime"), it.get("relative_depth"))
                except Exception:
                    head = ""
                body = ""
                if inc:
                    try:
                        idx = int(it.get("index", -1))
                        b = self.history.get_body(idx, offset=0, limit=-1)
                        body = b if b else ""
                    except Exception:
                        body = ""
                lines.append(head + ("BODY:\n" + body if inc else ""))
            self.large_context_buffer = "\n".join(lines)
            try:
                self.modelio_area.setText("Large context pack length=" + str(len(self.large_context_buffer)))
            except Exception:
                pass
        except Exception:
            pass

    def _refresh_queue_view(self):
        lines = []
        for i, q in enumerate(self.queue):
            lines.append("#{} {} {} approved={}".format(i, q.get("method"), q.get("url"), q.get("approved")))
        self.queue_area.setText("\n".join(lines))

    def _approve_next(self):
        if not self.queue:
            return
        self.queue[0]["approved"] = True
        self._refresh_queue_view()

    def _reject_next(self):
        if not self.queue:
            return
        self.queue.pop(0)
        self._refresh_queue_view()

    def _send_next(self):
        if not self.queue:
            return
        item = self.queue[0]
        if not item.get("approved"):
            self._append_chat("assistant", "next request not approved")
            return
        self.queue.pop(0)
        self._refresh_queue_view()
        self._dispatch_request(item)

    def _refresh_queue_view(self):
        try:
            if not self.queue:
                self.ui.queue_area.setText("(empty)")
                return
            lines = []
            for i, item in enumerate(self.queue):
                st = "APPROVED" if item.get("approved") else "PENDING"
                lines.append("[{}] {} {} ({})".format(i, item.get("method"), item.get("url"), st))
            self.ui.queue_area.setText("\n".join(lines))
        except Exception:
            pass

    def _dispatch_request(self, item):
        try:
            now = time.time()
            self.send_times = [t for t in self.send_times if now - t < 60]
            if len(self.send_times) >= self.store.get_rpm_limit():
                self._append_chat("assistant", "rate limit exceeded")
                return
            self.send_times.append(now)
            u = URL(item.get("url"))
            host = u.getHost()
            use_https = (u.getProtocol() or "").lower() == "https"
            port = u.getPort()
            if port == -1:
                port = 443 if use_https else 80
            path = u.getPath()
            query = u.getQuery()
            if query:
                path = path + "?" + query
            method = item.get("method", "GET")
            headers = item.get("headers") or {}
            headers = self._merge_session_headers(host, headers)
            if "Host" not in headers:
                headers["Host"] = host
            start = method + " " + path + " HTTP/1.1\r\n"
            hdr = "".join([k + ": " + str(v) + "\r\n" for k, v in headers.items()])
            body = item.get("body") or ""
            req_str = start + hdr + "\r\n" + (body if body else "")
            srv = self.helpers.buildHttpService(host, port, use_https)
            resp = self.callbacks.makeHttpRequest(srv, self.helpers.stringToBytes(req_str))
            rbytes = resp.getResponse()
            if rbytes:
                info = self.helpers.analyzeResponse(rbytes)
                status = info.getStatusCode()
                off = info.getBodyOffset()
                rb = self.helpers.bytesToString(rbytes)[off:]
                self.ui.modelio_area.setText("Sent: {} {}\nStatus: {}\nBody:\n{}".format(method, item.get("url"), status, rb[:2000]))
            else:
                self.ui.modelio_area.setText("No response")
        except Exception as e:
            self.ui.modelio_area.setText("Dispatch error: " + str(e))

    def _merge_session_headers(self, host, headers):
        out = dict(headers or {})
        try:
            items = self.callbacks.getProxyHistory()
        except Exception as e:
            items = []
            try:
                print("Proxy history error: " + str(e))
            except Exception:
                pass
        for it in reversed(items[-200:]):
            try:
                req = self.helpers.analyzeRequest(it)
                url = str(req.getUrl())
                if host in url:
                    for h in req.getHeaders()[1:]:
                        i = h.find(":")
                        if i > 0:
                            k = h[:i]
                            v = h[i+1:].strip()
                            lk = k.lower()
                            if lk in ("cookie", "authorization") and k not in out:
                                out[k] = v
                    break
            except Exception as e:
                try:
                    print("Merge headers error: " + str(e))
                except Exception:
                    pass
        return out

    def _append_notebook(self, text):
        try:
            path = self.ui.notebook_field.getText() or self.store.get_notebook_path()
            with open(path, "ab") as f:
                f.write((text + "\n").encode("utf-8"))
        except Exception as e:
            try:
                self.ui.modelio_area.setText("Notebook error: " + str(e))
            except Exception:
                pass

    def _default_chat_dir(self):
        d = os.path.join(os.path.expanduser("~"), "burpai_chats")
        try:
            if not os.path.exists(d):
                os.makedirs(d)
        except Exception as e:
            try:
                print("Chat dir error: " + str(e))
            except Exception:
                pass
        return d

    def _quick_save_chat(self):
        try:
            d = self._default_chat_dir()
            ts = time.strftime("%Y%m%d_%H%M%S")
            p = os.path.join(d, "chat_" + ts + ".html")
            with open(p, "wb") as f:
                f.write(self.chat_view.getText().encode("utf-8"))
            JOptionPane.showMessageDialog(self.root, "Chat saved: " + p)
        except Exception as e:
            JOptionPane.showMessageDialog(self.root, "Save error: " + str(e))

    def _quick_load_chat(self):
        try:
            d = self._default_chat_dir()
            files = sorted([os.path.join(d, x) for x in os.listdir(d) if x.endswith('.html')])
            if not files:
                return
            p = files[-1]
            with open(p, "rb") as f:
                self.ui.chat_view.setText(f.read().decode("utf-8"))
        except Exception as e:
            try:
                self.ui.modelio_area.setText("Load error: " + str(e))
            except Exception:
                pass
