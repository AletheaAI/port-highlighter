# -*- coding: utf-8 -*-
"""
Port Highlighter + AI Access Control Tester - Burp Suite Extension
-------------------------------------------------------------------------
1. Highlights Proxy History by listener port (like PwnFox, port-based).
2. Tracks sessions per port (cookies/tokens).
3. Cross-replays requests across roles to find IDOR / privilege escalation.
4. Uses AI (OpenAI / OpenRouter) to analyze whether a cross-port replay
   succeeded where it shouldn't -- real access-control findings.

Configure ROLE_MAPPINGS + AI_API_KEY below.
"""
from burp import (
    IBurpExtender,
    IProxyListener,
    IScannerCheck,
    IScanIssue,
)
from java.net import URL, HttpURLConnection
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
import json
import re
import time
import traceback

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION -- Edit these
# ═══════════════════════════════════════════════════════════════════════════

# Port -> (color, role) mapping.
# Role "admin" = requests worth testing against "user" sessions.
# Role "user"  = sessions used for replay.
ROLE_MAPPINGS = {
    8082: {"color": "red",    "role": "admin"},
    8083: {"color": "green",  "role": "user"},
    # 8084: {"color": "blue",   "role": "admin"},
}

# OpenAI-compatible API (OpenAI, OpenRouter, local LLM, etc.)
AI_API_KEY = ""          # Set your key here or via env var OPENAI_API_KEY
AI_BASE_URL = "https://api.openai.com/v1/chat/completions"
AI_MODEL = "gpt-4o-mini"  # cheap + fast

# How many cross-port replays before sending to AI (batch analysis saves cost)
BATCH_SIZE = 5

# Minimum content-length difference (%) to consider suspicious (before AI)
MIN_CONTENT_DIFF_PCT = 10

# If true, runs automatically. If false, you trigger manually via UI.
AUTO_TEST = True

# ═══════════════════════════════════════════════════════════════════════════
# INTERNAL
# ═══════════════════════════════════════════════════════════════════════════
SETTINGS_PREFIX = "port_highlighter."
SESSIONS_CAP = 50          # max requests remembered per port
ALL_COLORS = [
    "red", "orange", "yellow", "green", "cyan",
    "blue", "pink", "magenta", "gray", "none",
]


def _parse_port(listener_str):
    """Extract port number from listener string like '127.0.0.1:8082'."""
    if not listener_str:
        return None
    m = re.search(r':(\d+)$', listener_str)
    if m:
        return int(m.group(1))
    m = re.search(r'^(\d+)$', listener_str.strip())
    if m:
        return int(m.group(1))
    return None


def _extract_session(port, request_bytes, helpers):
    """
    Pull out the auth-relevant parts of a request.
    Returns a dict with cookies + authorization header.
    """
    try:
        info = helpers.analyzeRequest(request_bytes)
        headers = info.getHeaders()
        cookies = {}
        auth_header = None
        for h in headers:
            h = str(h)
            if h.lower().startswith("cookie:"):
                raw = h.split(":", 1)[1].strip()
                for pair in raw.split(";"):
                    pair = pair.strip()
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        cookies[k.strip()] = v.strip()
            elif h.lower().startswith("authorization:"):
                auth_header = h.split(":", 1)[1].strip()
        return {"port": port, "cookies": cookies, "auth": auth_header,
                "timestamp": time.time()}
    except Exception:
        return None


def _replace_session(request_bytes, session, helpers):
    """
    Rebuild a request with the target session's cookies + auth header.
    """
    try:
        info = helpers.analyzeRequest(request_bytes)
        headers = info.getHeaders()
        body_offset = info.getBodyOffset()
        body = request_bytes[body_offset:].tostring() if body_offset < len(request_bytes) else ""

        new_headers = []
        cookie_found = False
        auth_found = False

        for h in headers:
            h_str = str(h)
            if h_str.lower().startswith("cookie:"):
                # Replace with target session cookies
                parts = []
                for k, v in session.get("cookies", {}).items():
                    parts.append("%s=%s" % (k, v))
                if parts:
                    new_headers.append("Cookie: " + "; ".join(parts))
                cookie_found = True
            elif h_str.lower().startswith("authorization:"):
                if session.get("auth"):
                    new_headers.append("Authorization: " + session["auth"])
                auth_found = True
            else:
                new_headers.append(h_str)

        if not cookie_found and session.get("cookies"):
            parts = []
            for k, v in session["cookies"].items():
                parts.append("%s=%s" % (k, v))
            new_headers.append("Cookie: " + "; ".join(parts))
        if not auth_found and session.get("auth"):
            new_headers.append("Authorization: " + session["auth"])

        return helpers.buildHttpMessage(new_headers, body)
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════
# AI Client
# ═══════════════════════════════════════════════════════════════════════════

class AIClient(object):

    def __init__(self, api_key, base_url, model, ext):
        self.api_key = api_key or ext._callbacks.loadExtensionSetting(
            SETTINGS_PREFIX + "ai_key"
        ) or ""
        self.base_url = base_url
        self.model = model
        self.ext = ext

    def analyze(self, findings):
        """Send a batch of findings to the AI for analysis."""
        if not self.api_key:
            self.ext._callbacks.printError(
                "[AccessControl] No AI API key set. Skipping AI analysis."
            )
            return

        prompt = self._build_prompt(findings)
        try:
            resp = self._call_api(prompt)
            return resp
        except Exception as e:
            self.ext._callbacks.printError("[AI] Request failed: %s" % e)
            return None

    def _build_prompt(self, findings):
        parts = []
        parts.append(
            "You are a penetration testing assistant. Below are HTTP "
            "requests replayed from an admin session into a regular user's "
            "session. For each pair, determine if there is a "
            "real access-control vulnerability (IDOR, privilege escalation, "
            "missing authorization).\n"
            "Only report findings where the user SHOULD NOT have been able "
            "to access the resource but DID.\n\n"
        )
        for i, f in enumerate(findings):
            parts.append("--- Finding %d ---\n" % (i + 1))
            parts.append("URL: %s\n" % f.get("url", "?"))
            parts.append("Method: %s\n" % f.get("method", "?"))
            parts.append("Admin status: %d\n" % f.get("admin_status", 0))
            parts.append("User status: %d\n" % f.get("user_status", 0))
            parts.append("Admin body (truncated): %s\n" %
                         (f.get("admin_body", "")[:1000]))
            parts.append("User body (truncated): %s\n" %
                         (f.get("user_body", "")[:1000]))
            parts.append("\n")

        parts.append(
            "Respond in JSON format:\n"
            '{"findings": ['
            '{"vulnerable": true/false, '
            '"severity": "high/medium/low/info", '
            '"title": "short title", '
            '"description": "detailed explanation"}]}'
        )
        return "".join(parts)

    def _call_api(self, prompt):
        url = URL(self.base_url)
        conn = url.openConnection()
        conn.setRequestMethod("POST")
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("Authorization", "Bearer " + self.api_key)
        conn.setDoOutput(True)
        conn.setConnectTimeout(30000)
        conn.setReadTimeout(60000)

        body = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a security expert."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        })

        writer = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
        writer.write(body)
        writer.close()

        reader = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
        lines = []
        while True:
            line = reader.readLine()
            if line is None:
                break
            lines.append(line)
        reader.close()
        conn.disconnect()

        return json.loads("".join(lines))


# ═══════════════════════════════════════════════════════════════════════════
# Burp Extension
# ═══════════════════════════════════════════════════════════════════════════

class BurpExtender(IBurpExtender, IProxyListener, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Port Highlighter + Access Control")

        # ── Port -> (color, role) ──
        self.port_config = dict(ROLE_MAPPINGS)
        self._load_role_mappings()

        # ── Sessions per port ──
        # {port: [session_dict, ...]}
        self._sessions = {}

        # ── Pending findings batch ──
        self._pending_findings = []

        # ── AI client ──
        self.ai = AIClient(AI_API_KEY, AI_BASE_URL, AI_MODEL, self)

        # ── Register proxy listener ──
        callbacks.registerProxyListener(self)

        # ── Register scanner check (passive) ──
        callbacks.registerScannerCheck(self)

        # ── Output ──
        callbacks.printOutput("=" * 50)
        callbacks.printOutput("Port Highlighter + Access Control Tester")
        callbacks.printOutput("=" * 50)
        for port, cfg in sorted(self.port_config.items()):
            callbacks.printOutput(
                "  Port %d -> %s (%s)" %
                (port, cfg.get("color", "?"), cfg.get("role", "?"))
            )
        callbacks.printOutput("AI: %s" %
                              ("enabled" if self.ai.api_key else "disabled (set AI_API_KEY)"))
        callbacks.printOutput("Auto-test: %s" %
                              ("ON" if AUTO_TEST else "OFF"))
        callbacks.printOutput("=" * 50)

        # ── Context menu: "Test Access Control" on any proxy item ──
        callbacks.registerContextMenuFactory(
            _MenuFactory(self)
        )

    # ── Proxy Listener ──────────────────────────────────────────────────

    def processProxyMessage(self, messageIsRequest, message):
        port = _parse_port(message.getListenerInterface())
        if port is None:
            return
        if port not in self.port_config:
            return
        cfg = self.port_config[port]

        # Highlight
        if messageIsRequest:
            color = cfg.get("color")
            if color:
                try:
                    message.getMessageInfo().setHighlight(color)
                except Exception:
                    pass

        # Session tracking -- capture cookies/tokens per port
        if AUTO_TEST:
            self._track_session(port, messageIsRequest, message)

    # ── Session tracking ────────────────────────────────────────────────

    def _track_session(self, port, messageIsRequest, message):
        """Store request sessions per port, then cross-test."""
        if not messageIsRequest:
            return

        request_bytes = message.getMessageInfo().getRequest()
        session = _extract_session(port, request_bytes, self._helpers)
        if session is None:
            return

        if port not in self._sessions:
            self._sessions[port] = []
        self._sessions[port].append(session)
        if len(self._sessions[port]) > SESSIONS_CAP:
            self._sessions[port] = self._sessions[port][-SESSIONS_CAP:]

        # Cross-test: if this is an admin request, replay with user sessions
        role = self.port_config[port].get("role")
        if role == "admin":
            self._cross_test(port, request_bytes, message)

    def _cross_test(self, admin_port, admin_request_bytes, message):
        """Replay admin request through each user port's session."""
        target_ports = [
            p for p, c in self.port_config.items()
            if c.get("role") == "user" and p in self._sessions
        ]
        if not target_ports:
            return

        # Get admin response for comparison
        admin_info = self._helpers.analyzeRequest(admin_request_bytes)
        admin_url = str(admin_info.getUrl())

        # Skip static files, images, etc.
        skip_ext = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css",
                     ".js", ".woff", ".woff2", ".ttf", ".ico", ".map")
        if admin_url.lower().endswith(skip_ext):
            return

        for user_port in target_ports:
            sessions = self._sessions.get(user_port, [])
            if not sessions:
                continue

            # Use the most recent user session
            user_session = sessions[-1]
            user_request = _replace_session(
                admin_request_bytes, user_session, self._helpers
            )
            if user_request is None:
                continue

            try:
                # Send as user
                admin_svc = message.getMessageInfo().getHttpService()
                user_resp = self._callbacks.makeHttpRequest(
                    admin_svc.getHost(),
                    admin_svc.getPort(),
                    admin_svc.getProtocol() == "https",
                    user_request
                )

                # Compare
                admin_resp = message.getMessageInfo().getResponse()
                if admin_resp is None:
                    continue

                finding = self._compare_responses(
                    admin_url, admin_request_bytes, admin_resp,
                    user_request, user_resp,
                    admin_port, user_port
                )
                if finding:
                    self._pending_findings.append(finding)
                    self._callbacks.printOutput(
                        "[!] Potential: %s (admin=%d, user=%d)" %
                        (admin_url, finding["admin_status"],
                         finding["user_status"])
                    )

                    # Batch AI analysis
                    if len(self._pending_findings) >= BATCH_SIZE:
                        self._run_ai_analysis()

            except Exception as e:
                self._callbacks.printError(
                    "[CrossTest] Error replaying %s through port %d: %s" %
                    (admin_url, user_port, e)
                )

    def _compare_responses(self, url, admin_req, admin_resp,
                           user_req, user_resp, admin_port, user_port):
        """Compare admin vs user response. Return finding if suspicious."""
        try:
            admin_info = self._helpers.analyzeResponse(admin_resp)
            user_info = self._helpers.analyzeResponse(user_resp)

            admin_status = admin_info.getStatusCode()
            user_status = user_info.getStatusCode()
            admin_body_offset = admin_info.getBodyOffset()
            user_body_offset = user_info.getBodyOffset()
            admin_body = admin_resp[admin_body_offset:].tostring() if admin_body_offset < len(admin_resp) else ""
            user_body = user_resp[user_body_offset:].tostring() if user_body_offset < len(user_resp) else ""

            # Quick heuristics
            # 1. Both return 2xx/3xx and similar body -> possible privilege escalation
            if (200 <= admin_status < 400 and 200 <= user_status < 400):
                len_diff = abs(len(admin_body) - len(user_body))
                max_len = max(len(admin_body), len(user_body), 1)
                pct = (float(len_diff) / max_len) * 100.0

                if pct < MIN_CONTENT_DIFF_PCT:
                    # Nearly identical response -- very suspicious
                    return {
                        "url": url,
                        "method": str(self._helpers.analyzeRequest(admin_req).getMethod()),
                        "admin_port": admin_port,
                        "user_port": user_port,
                        "admin_status": admin_status,
                        "user_status": user_status,
                        "admin_body": admin_body,
                        "user_body": user_body,
                        "content_diff_pct": pct,
                    }

            # 2. User gets 2xx where admin gets 4xx/5xx (inverted -- weird but worth noting)
            if (200 <= user_status < 400 and admin_status >= 400):
                return {
                    "url": url,
                    "method": str(self._helpers.analyzeRequest(admin_req).getMethod()),
                    "admin_port": admin_port,
                    "user_port": user_port,
                    "admin_status": admin_status,
                    "user_status": user_status,
                    "admin_body": admin_body,
                    "user_body": user_body,
                    "content_diff_pct": 100.0,
                }

        except Exception:
            pass
        return None

    # ── AI Analysis ─────────────────────────────────────────────────────

    def _run_ai_analysis(self):
        if not self._pending_findings:
            return
        batch = self._pending_findings[:]
        self._pending_findings = []

        self._callbacks.printOutput(
            "\n[AI] Analyzing %d potential access-control issues ..." %
            len(batch)
        )
        result = self.ai.analyze(batch)
        if result is None:
            self._callbacks.printOutput("[AI] Analysis skipped (no API key or error).")
            self._callbacks.printOutput(
                "  Review these URLs manually:"
            )
            for f in batch:
                self._callbacks.printOutput(
                    "  - %s (admin=%d / user=%d)" %
                    (f["url"], f["admin_status"], f["user_status"])
                )
            return

        try:
            ai_findings = result.get("choices", [{}])[0].get(
                "message", {}
            ).get("content", "{}")
            parsed = json.loads(ai_findings)
            self._report_findings(batch, parsed.get("findings", []))
        except Exception as e:
            self._callbacks.printError("[AI] Failed to parse response: %s" % e)

    def _report_findings(self, raw_findings, ai_results):
        for i, ai in enumerate(ai_results):
            if i >= len(raw_findings):
                break
            if not ai.get("vulnerable"):
                continue
            f = raw_findings[i]
            self._callbacks.printOutput("")
            self._callbacks.printOutput("▼" * 40)
            self._callbacks.printOutput(
                "[%s] %s" % (ai.get("severity", "?").upper(),
                              ai.get("title", "Access Control Issue"))
            )
            self._callbacks.printOutput("URL: %s" % f["url"])
            self._callbacks.printOutput(
                "Admin port %d (status %d) vs User port %d (status %d)" %
                (f["admin_port"], f["admin_status"],
                 f["user_port"], f["user_status"])
            )
            self._callbacks.printOutput(ai.get("description", ""))
            self._callbacks.printOutput("▲" * 40)

    # ── Manual test trigger ─────────────────────────────────────────────

    def run_manual_test(self, http_message):
        """Called from context menu. Test a single item."""
        port = None
        # We don't have the listener port from the context menu directly,
        # so we treat the selected item as admin and test against all user sessions.
        admin_req = http_message.getRequest()
        admin_resp = http_message.getResponse()
        if admin_resp is None:
            self._callbacks.printOutput(
                "[Manual] No response available for this item."
            )
            return

        target_ports = [
            p for p, c in self.port_config.items()
            if c.get("role") == "user" and p in self._sessions
        ]
        if not target_ports:
            self._callbacks.printOutput(
                "[Manual] No user sessions captured yet. "
                "Browse through a user port first."
            )
            return

        admin_info = self._helpers.analyzeRequest(admin_req)
        admin_url = str(admin_info.getUrl())

        findings = []
        for user_port in target_ports:
            sessions = self._sessions.get(user_port, [])
            if not sessions:
                continue
            user_session = sessions[-1]
            user_req = _replace_session(
                admin_req, user_session, self._helpers
            )
            if user_req is None:
                continue

            svc = http_message.getHttpService()
            user_resp = self._callbacks.makeHttpRequest(
                svc.getHost(), svc.getPort(),
                svc.getProtocol() == "https", user_req
            )

            finding = self._compare_responses(
                admin_url, admin_req, admin_resp,
                user_req, user_resp, -1, user_port
            )
            if finding:
                findings.append(finding)

        if findings:
            self._callbacks.printOutput(
                "\n[Manual] Found %d potential issues. Running AI ..." %
                len(findings)
            )
            result = self.ai.analyze(findings)
            if result:
                try:
                    ai = result.get("choices", [{}])[0].get(
                        "message", {}
                    ).get("content", "{}")
                    self._report_findings(findings,
                                         json.loads(ai).get("findings", []))
                except Exception as e:
                    self._callbacks.printError("[Manual] AI parse error: %s" % e)
        else:
            self._callbacks.printOutput("[Manual] No issues detected.")

    # ── Persistence helpers ─────────────────────────────────────────────

    def _load_role_mappings(self):
        raw = self._callbacks.loadExtensionSetting(
            SETTINGS_PREFIX + "mappings"
        )
        if raw:
            try:
                data = json.loads(raw)
                for port_str, val in data.items():
                    port = int(port_str)
                    if isinstance(val, dict):
                        self.port_config[port] = val
                    else:
                        # Old format: just color string
                        self.port_config[port] = {"color": val, "role": "user"}
            except Exception:
                pass

    # ── IScannerCheck (passive scanning) ────────────────────────────────

    def doPassiveScan(self, baseRequestResponse):
        return []  # Passive reporting done via AI batch

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return -1  # Don't deduplicate

    def _get_listener_port(self):
        """Not used here but kept for reference."""
        pass


# ═══════════════════════════════════════════════════════════════════════════
# Context Menu Factory
# ═══════════════════════════════════════════════════════════════════════════

from javax.swing import JMenuItem, JOptionPane
from java.awt.event import ActionListener


class _MenuFactory(object):
    """Adds a right-click menu item to test access control."""

    def __init__(self, ext):
        self._ext = ext

    def createMenuItems(self, invocation):
        items = []
        messages = invocation.getSelectedMessages()
        if not messages:
            return items

        item = JMenuItem("Test Access Control (AI)")
        item.addActionListener(_TestListener(self._ext, messages[0]))
        items.append(item)

        # Also add context actions to switch AI / auto-test settings
        toggle_on = JMenuItem("Auto-Test: ON" if AUTO_TEST else "Auto-Test: OFF")
        toggle_on.addActionListener(_ToggleAutoListener(self._ext))
        items.append(toggle_on)

        return items


class _TestListener(ActionListener):
    def __init__(self, ext, message):
        self._ext = ext
        self._msg = message

    def actionPerformed(self, event):
        self._ext.run_manual_test(self._msg)


class _ToggleAutoListener(ActionListener):
    def __init__(self, ext):
        self._ext = ext

    def actionPerformed(self, event):
        # To toggle: just edit AUTO_TEST above and reload
        JOptionPane.showMessageDialog(
            None,
            "Edit AUTO_TEST in port_highlighter.py and reload the extension.",
            "Toggle Auto-Test",
            JOptionPane.INFORMATION_MESSAGE,
        )
