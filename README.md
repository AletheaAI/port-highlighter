# Port Highlighter

Burp Suite extension that highlights HTTP requests in **Proxy History** based on the **listener port** they arrived through.

If you pentest multiple devices simultaneously (e.g., iOS on port 8082, Android on port 8083), this extension color-codes each device's traffic so you can visually separate them at a glance — same idea as [PwnFox](https://github.com/yeswehack/PwnFox) container highlighting, but port-based.

![](screenshot.png)

## Default Mappings

| Listener Port | Highlight Color |
|---------------|-----------------|
| 8082          | Red             |
| 8083          | Green           |

Edit `DEFAULT_MAPPINGS` in the script to add your own port/color pairs.

Available colors: `red`, `orange`, `yellow`, `green`, `cyan`, `blue`, `pink`, `magenta`, `gray`, `none`.

## Installation

1. Install Jython for Burp:
   ```bash
   brew install jython
   ```
2. In Burp: **Extender → Extensions → Add**
   - Extension type: **Python**
   - Select `port_highlighter.py`
3. Verify the "Port Highlighter" tab appears and the output panel shows loaded mappings.

## Setup

In **Proxy → Proxy Settings → Proxy Listeners**, create listeners for your devices:

- `127.0.0.1:8082` → Device A
- `127.0.0.1:8083` → Device B

Configure each device/browser to proxy through its respective port. Requests will appear color-coded in Proxy History.

## Custom Ports & Colors

Open `port_highlighter.py` and edit this dictionary:

```python
DEFAULT_MAPPINGS = {
    8082: "red",
    8083: "green",
    8080: "orange",   # add more
    8084: "blue",
}
```

Reload the extension after changes.

## License

MIT — do whatever you want.
