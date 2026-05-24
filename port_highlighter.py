# -*- coding: utf-8 -*-
"""
Port Highlighter - Burp Suite Extension
Highlights HTTP requests in Proxy History based on the listening port.

Similar to PwnFox container-based highlighting but port-based.
Example: device A on 127.0.0.1:8082 -> RED, device B on 127.0.0.1:8083 -> GREEN

Configure colors by editing DEFAULT_MAPPINGS below.
"""
from burp import IBurpExtender, IProxyListener
import json
import re

# Edit these to change port -> color mappings
# Color names: red, orange, yellow, green, cyan, blue, pink, magenta, gray, none
DEFAULT_MAPPINGS = {
    8082: "red",
    8083: "green",
}

SETTINGS_PREFIX = "port_highlighter."


class BurpExtender(IBurpExtender, IProxyListener):
    """
    Burp extension that color-codes proxy history entries by listener port.
    Implements IBurpExtender. Uses duck typing for IProxyListener (Jython
    will call processProxyMessage on any registered object).
    """

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Port Highlighter")

        # Load port -> color mappings from Burp settings
        self.port_color_map = self._load_mappings()

        # Register self as proxy listener (works via duck typing)
        callbacks.registerProxyListener(self)

        callbacks.printOutput("[Port Highlighter] Loaded successfully.")
        callbacks.printOutput("Port mappings:")
        for port in sorted(self.port_color_map.keys()):
            callbacks.printOutput("  Port %d -> %s" %
                                  (port, self.port_color_map[port]))
        callbacks.printOutput("")

    # ── IProxyListener (duck typing) ────────────────────────────────────

    def processProxyMessage(self, messageIsRequest, message):
        """
        Called for every request/response passing through the proxy.
        We highlight the proxy history entry based on the listener port.
        """
        if not messageIsRequest:
            # Only color on the request leg; response inherits the color.
            return

        port = self._get_listener_port(message)
        if port is None:
            return

        color = self.port_color_map.get(port)
        if color is not None:
            try:
                http_msg = message.getMessageInfo()
                http_msg.setHighlight(color)
            except Exception:
                pass

    # ── Listener port detection ─────────────────────────────────────────

    def _get_listener_port(self, message):
        """
        Parse the listener port from getListenerInterface().
        Returns a string like "127.0.0.1:8082" or just "8082".
        """
        try:
            listener_str = message.getListenerInterface()
            if listener_str:
                # "address:port"
                m = re.search(r':(\d+)$', listener_str)
                if m:
                    return int(m.group(1))
                # Bare port number
                m = re.search(r'^(\d+)$', listener_str.strip())
                if m:
                    return int(m.group(1))
        except Exception:
            pass
        return None

    # ── Persistence ─────────────────────────────────────────────────────

    def _load_mappings(self):
        try:
            raw = self._callbacks.loadExtensionSetting(
                SETTINGS_PREFIX + "mappings"
            )
            if raw:
                data = json.loads(raw)
                result = {}
                for port_str, color in data.items():
                    result[int(port_str)] = color
                return result if result else dict(DEFAULT_MAPPINGS)
        except Exception:
            pass
        return dict(DEFAULT_MAPPINGS)

    def _save_mappings(self, port_color_map):
        data = {}
        for port, color in port_color_map.items():
            data[str(port)] = color
        self._callbacks.saveExtensionSetting(
            SETTINGS_PREFIX + "mappings", json.dumps(data)
        )
