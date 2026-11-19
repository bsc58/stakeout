"""Read a HAR 1.2 file written by a man-in-the-middle proxy (mitmproxy `hardump`, Charles,
Proxyman, HTTP Toolkit, Chrome) into exchange records (docs/CONTRACT_DECRYPT.md).

What is taken from where, and why:

- Time: `startedDateTime`, converted to the phone's local time. An entry whose time has no
  UTC offset (or cannot be read) is skipped: its moment is not known.
- Host, path, query: from `request.url`, the target as sent. `queryString` is ignored
  because tools disagree on whether its values are percent-decoded; the pairs are decoded
  here from the URL (`+` is a space; a value that is not valid UTF-8 after percent-decoding
  is kept as sent). An empty path is "/" (what an HTTP client sends). The host is in Host
  header form, lower case, without the scheme's default port (443 for https, 80 for http).
  Entries with a scheme other than http/https/ws/wss are skipped; ws/wss count as http/https.
- Bodies: HAR 1.2 stores content after the proxy removed Content-Encoding (the headers still
  say gzip), so Content-Encoding is never applied again: BODY describes the content as saved,
  its size and sha256 are of that content, and its `encoding` is None. Base64 content is
  exact. Text content is turned back into bytes only when that is certain: pure ASCII, or a
  charset declared in Content-Type, or JSON (UTF-8) without one; text with U+FFFD or with
  characters the charset cannot encode is not, nor is any text under a declared UTF-16/32
  charset (the original's byte order and BOM are not in the text). Otherwise the proxy picked a charset itself
  (mitmproxy saves a binary request body as Latin-1 text) and the bytes are not known: BODY
  then has size, sha256 and preview_hex None, decoded False, and the exchange gets
  `body_not_decoded`. postData with `params` but no `text` is not rebuilt (`body_not_decoded`).
- A body that the HAR left out although `bodySize` > 0 (mitmproxy keeps postData only for
  POST/PUT/PATCH) makes that side incomplete: `request_incomplete` / `response_incomplete`.
- No response, or status 0 (mitmproxy and Chrome write that for a request that got no
  answer): response None and `response_not_matched`.
- Chrome entries served from its cache (`_fromCache`) were not sent: skipped.
- CONNECT entries are a proxy's record of a tunnel request (mitmproxy writes the URL as
  `https://host:port/`, a path that was never sent) and carry no decrypted content: skipped.
- `protocol` from `request.httpVersion`: "http/1.1", "h2", and also "http/1.0", "h3", or None
  when the version is missing or unknown.
- Header names and values, method and URL: mitmproxy keeps bytes that are not UTF-8 as lone
  surrogates (surrogateescape; JSON `\\udcXX`). Those bytes are recovered exactly and given as
  Latin-1, as aw/h2.py does for the same bytes from eCapture; any other lone surrogate is shown
  as a `\\uXXXX` escape. Left as they are, they cannot be written to result.json.
"""
import base64
import binascii
import json
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote_plus, urlsplit

from aw.exchange import header, make_body

_OFFSET = re.compile(r"([+-])(\d\d):?(\d\d)")
_CHARSET = re.compile(r"(?i)charset=\"?([A-Za-z0-9._-]+)")      # as aw.exchange reads it
_SCHEMES = {"https": "https", "wss": "https", "http": "http", "ws": "http"}
_DEFAULT_PORT = {"https": 443, "http": 80}
_PROTOCOLS = {"http/1.0": "http/1.0", "http/1.1": "http/1.1",
              "http/2": "h2", "http/2.0": "h2", "h2": "h2",
              "http/3": "h3", "http/3.0": "h3", "h3": "h3"}


def _tz(utc_offset):
    m = _OFFSET.fullmatch(utc_offset.strip())
    if not m:
        raise ValueError(f"utc_offset {utc_offset!r} is not ±HHMM")
    d = timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
    return timezone(-d if m.group(1) == "-" else d)


def _started(value):
    """startedDateTime -> aware datetime, or None (missing, unreadable, no UTC offset)."""
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


def _str(s):
    """A HAR string as it can be stored (see the module docstring)."""
    try:
        s.encode("utf-8")
        return s
    except UnicodeEncodeError:
        pass
    try:
        return s.encode("utf-8", "surrogateescape").decode("latin-1")
    except UnicodeEncodeError:
        return s.encode("utf-8", "backslashreplace").decode("utf-8")


def _headers(items):
    if not isinstance(items, list):
        return []
    return [[_str(h["name"]), _str(h["value"])] for h in items
            if isinstance(h, dict) and isinstance(h.get("name"), str) and isinstance(h.get("value"), str)]


def _unquote(s):
    try:
        return unquote_plus(s, errors="strict")
    except UnicodeDecodeError:
        return s


def _query(qs):
    pairs = []
    for part in qs.split("&"):
        if part:
            name, _, value = part.partition("=")
            pairs.append([_unquote(name), _unquote(value)])
    return pairs


def _target(url):
    """request.url -> (scheme, host, path, query) or None when it is not a usable http(s) URL."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = _SCHEMES.get(parts.scheme.lower())
    if scheme is None or not parts.hostname:
        return None
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    if port is not None and port != _DEFAULT_PORT[scheme]:
        host = f"{host}:{port}"
    return scheme, host, parts.path or "/", _query(parts.query)


def _text_bytes(text, content_type):
    """HAR text -> the bytes that were sent, or None when they are not certain."""
    m = _CHARSET.search(content_type or "")
    if m:
        try:
            wide = "a".encode(m.group(1)) != b"a"
        except LookupError:
            wide = False
        if wide:        # UTF-16/32: byte order and BOM of the original are not in the text
            return None
    if text.isascii():
        return text.encode("ascii")
    if m:
        charset = m.group(1)
    elif (content_type or "").split(";")[0].strip().lower().endswith(("/json", "+json")):
        charset = "utf-8"
    else:
        return None
    if "�" in text:
        return None
    try:
        return text.encode(charset)
    except (UnicodeEncodeError, LookupError):
        return None


def _undecoded():
    return {"size": None, "sha256": None, "encoding": None, "encoding_detected": False, "decoded": False,
            "kind": "binary", "text": None, "truncated": False, "preview_hex": None}


def _body(text, encoding, content_type):
    """Non-empty HAR postData/content text (already without Content-Encoding) -> (BODY, certain)."""
    raw = None
    if not isinstance(text, str):
        pass
    elif encoding == "base64":
        try:
            raw = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            raw = None
    elif not encoding:
        raw = _text_bytes(text, content_type)
    if raw is None:
        return _undecoded(), False
    return make_body(raw, content_type, None), True


def _body_size(d):
    n = d.get("bodySize")
    return n if isinstance(n, int) and not isinstance(n, bool) else -1


def _exchange(entry, tz):
    """One HAR entry -> (sort key, EXCHANGE), or None when it has no usable request."""
    if not isinstance(entry, dict) or entry.get("_fromCache"):
        return None
    req = entry.get("request")
    started = _started(entry.get("startedDateTime"))
    if not isinstance(req, dict) or started is None:
        return None
    method = req.get("method")
    url = req.get("url")
    target = _target(_str(url) if isinstance(url, str) else None)
    if not isinstance(method, str) or not method or method.upper() == "CONNECT" or target is None:
        return None
    method = _str(method)
    scheme, host, path, query = target
    partial = []

    req_headers = _headers(req.get("headers"))
    post = req.get("postData") if isinstance(req.get("postData"), dict) else {}
    req_type = header(req_headers, "content-type") or post.get("mimeType")
    req_complete = True
    if post.get("text"):
        req_body, certain = _body(post.get("text"), post.get("encoding"), req_type)
        if not certain:
            partial.append("body_not_decoded")
    elif post.get("params"):
        req_body = _undecoded()
        partial.append("body_not_decoded")
    else:
        req_body = None
        if _body_size(req) > 0:
            req_complete = False
            partial.append("request_incomplete")

    resp = entry.get("response")
    status = resp.get("status") if isinstance(resp, dict) else None
    if not isinstance(status, int) or isinstance(status, bool) or status <= 0:
        response = None
        partial.append("response_not_matched")
    else:
        resp_headers = _headers(resp.get("headers"))
        content = resp.get("content") if isinstance(resp.get("content"), dict) else {}
        resp_type = header(resp_headers, "content-type") or content.get("mimeType")
        resp_complete = True
        if content.get("text"):
            resp_body, certain = _body(content.get("text"), content.get("encoding"), resp_type)
            if not certain:
                partial.append("body_not_decoded")
        else:
            resp_body = None
            if _body_size(resp) > 0:
                resp_complete = False
                partial.append("response_incomplete")
        response = {"status": status, "headers": resp_headers, "body": resp_body,
                    "complete": resp_complete}

    local = started.astimezone(tz)
    version = req.get("httpVersion")
    return started, {
        "source": "har",
        "time": f"{local:%Y-%m-%d %H:%M:%S}.{local.microsecond // 1000:03d}",
        "protocol": _PROTOCOLS.get(version.strip().lower()) if isinstance(version, str) else None,
        "method": method, "scheme": scheme, "host": host, "path": path, "query": query,
        "request": {"headers": req_headers, "body": req_body, "complete": req_complete},
        "response": response,
        "pid": None, "thread": None,
        "partial": list(dict.fromkeys(partial)),
        "connection_host_tail": None,       # a proxy's HAR does not say which connection carried the request
    }


def parse_har(path, utc_offset="+0000") -> dict:
    """{"creator": "mitmproxy 11.0" | None, "entries": N, "skipped": N, "exchanges": [...]}.
    Raises ValueError (Chinese message) for a file that is not HAR."""
    tz = _tz(utc_offset)
    with open(path, "rb") as f:
        data = f.read()
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError(f"{path} 不是 HAR 文件：内容不是 JSON。") from None
    log = doc.get("log") if isinstance(doc, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f"{path} 不是 HAR 文件：没有 log.entries。")

    creator = log.get("creator") if isinstance(log.get("creator"), dict) else {}
    name = _str(" ".join(str(creator[k]) for k in ("name", "version") if creator.get(k)))

    rows = [r for r in (_exchange(e, tz) for e in entries) if r is not None]
    rows.sort(key=lambda r: r[0])
    return {"creator": name or None, "entries": len(entries), "skipped": len(entries) - len(rows),
            "exchanges": [x for _, x in rows]}
