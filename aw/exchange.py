"""Helpers shared by every source of decrypted traffic (parse_tls, parse_har) and by the
report. The shape of an exchange and of a body is in docs/CONTRACT_DECRYPT.md."""
import bisect
import functools
import hashlib
import json
import re
import zlib
from html import unescape as _html_unescape

BODY_TEXT_MAX = 64 * 1024      # characters of text kept per body
PREVIEW_BYTES = 64             # bytes shown as hex for a binary body

# What the report hides unless --show-secrets is given: the name stays, the value is replaced by its
# length. Four groups of names, and two shapes of value whatever the name.
_CREDENTIAL = (r"token|session|sessionid|sid|passwd|password|pwd|secret|auth|credential|credentials"
               r"|apikey|api[-_.]key|access[-_.]key")
_SIGNATURE = r"sig|sign|signature"
# Identifiers of the device, the installation and the account.
_IDENTITY = (r"device[-_.]?id|did|gid|uid|uuid|udid|guid|user[-_.]?id|openid|unionid|imei|imsi|meid"
             r"|oaid|vaid|aaid|idfa|idfv|android[-_.]?id|mac|serial")
# The client's network address, as servers echo it (xhs-real-ip, x-forwarded-for).
_ADDRESS = r"ip|ipaddr|ipaddress|ipv4|ipv6|forwarded"
_SENSITIVE = re.compile(
    r"^(?:cookie|set-cookie|authorization|proxy-authorization)$"
    r"|(?:^|[-_.])(?:" + "|".join((_CREDENTIAL, _SIGNATURE, _IDENTITY, _ADDRESS)) + r")(?:[-_.]|$)")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
# A signed token (JWT: base64url of a JSON object, a dot, more) and a long run of base64/hex
# characters with letters and digits: signatures, tokens and identifiers under names no list can
# know (x-mini-mua, x-mini-s1). A value that starts with "/" is a path, not such a run.
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_OPAQUE = re.compile(r"(?!/)(?=[^0-9]*[0-9])(?=[^A-Za-z]*[A-Za-z])[A-Za-z0-9+/_=-]{32,}")


def is_sensitive(name: str, value: str | None = None) -> bool:
    """True when the report must hide this header, query, form or JSON field: by its name
    (credential, signature, device or account identifier, client address; deviceId is read as
    device_id), or, when the value is given, by the value's shape (signed token, long opaque
    string)."""
    if _SENSITIVE.search(_CAMEL.sub("_", name or "").lower()):
        return True
    return value is not None and bool(_JWT.fullmatch(value) or _OPAQUE.fullmatch(value))


_KIND_RE = tuple((kind, re.compile(r"(?:^|[-_.])(?:" + group + r")(?:[-_.]|$)")) for kind, group in (
    ("credential", _CREDENTIAL), ("signature", _SIGNATURE), ("identity", _IDENTITY), ("address", _ADDRESS)))
_WHOLE_CREDENTIAL = re.compile(r"^(?:cookie|set-cookie|authorization|proxy-authorization)$")


def sensitive_kind(name: str):
    """The group for which is_sensitive(name) hides a value by its name: "credential", "signature", "identity"
    (device, installation and account identifiers) or "address" (the client's network address); the first that
    matches, in that order. None exactly when is_sensitive(name) is False."""
    n = _CAMEL.sub("_", name or "").lower()
    if _WHOLE_CREDENTIAL.match(n):
        return "credential"
    for kind, rx in _KIND_RE:
        if rx.search(n):
            return kind
    return None


def mask(value: str) -> str:
    """What the report shows in place of a hidden value: its length only."""
    return f"〈已隐藏，{len(value)} 个字符〉"


def mask_cut(value: str) -> str:
    """What the report shows by default in place of a value cut off where the recording ends (a body cut
    at BODY_TEXT_MAX or not recorded to its end): a part of a value cannot be judged by its shape."""
    return f"〈没有记录完整，不显示，{len(value)} 个字符〉"


# How the default report hides values. The functions below never rewrite a text: they find the spans of it
# to hide, (start, end, what to show instead), and apply_spans replaces those spans only. Everything else is
# shown as it was sent, so the default report and the --show-secrets one differ in the hidden values alone.
# A value is judged as it reads once decoded (percent escapes, HTML entities, JSON escapes), and what it holds
# is examined in turn: JSON, a URL, name=value fields. Every recursion works on a shorter string, so it ends.
# Each function takes `found`, the set that collects every value hidden (see hide): the report hides the other
# occurrences of those values too.

_URL_START = re.compile(r"/|[A-Za-z][A-Za-z0-9+.-]*://")     # a path, or a URL with a scheme
_VALUE_SEPS = "&;,?#"       # between fields in a header value or a string; spaces and line breaks too
_URL_ESC = re.compile(r"(?:%[0-9A-Fa-f]{2})+|&(?:#[0-9]{1,7}|#[xX][0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")
_JSON_ESC = re.compile(r'\\u[0-9A-Fa-f]{4}|\\["\\/bfnrt]')
_ANY_ESC = re.compile(_URL_ESC.pattern + "|" + _JSON_ESC.pattern)
_JSON_CHAR = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
_CUT = "〈没有记录完整，"


def hide(value: str, found: set | None = None, *raw: str) -> str:
    """mask(value), noting the value (and raw: the forms it was written in) in `found`, decoded: the report
    hides the other occurrences of a value it hides, in any of these forms."""
    if found is not None:
        for v in (value, *raw):
            v = v.strip()
            found.update((canon(v), canon(v.strip("\"'"))))
    return mask(value)


def _unescape(t):
    """The characters the escape t stands for, each with its offset in t; None when t is no escape."""
    if t[0] == "%":
        data, out, i = bytes.fromhex(t.replace("%", "")), [], 0
        while i < len(data):
            lead = data[i]
            n = 2 if lead >> 5 == 6 else 3 if lead >> 4 == 14 else 4 if lead >> 3 == 30 else 1
            try:
                c = data[i:i + n].decode("utf-8")
            except UnicodeDecodeError:
                c, n = "�", 1
            out.append((c, 3 * i))
            i += n
        return out
    if t[0] == "&":
        c = _html_unescape(t)
        return None if c == t else [(ch, 0) for ch in c]
    return [(chr(int(t[2:], 16)) if t[1] == "u" else _JSON_CHAR[t[1]], 0)]


def _decode(s, pattern):
    """(s with the escapes `pattern` finds replaced by what they stand for, offsets): offsets[i] is where
    character i of the result starts in s, with one more entry, len(s). (s, None) when nothing was decoded."""
    out, off, pos = [], [], 0
    for m in pattern.finditer(s):
        chars = _unescape(m[0])
        if chars is None:
            continue
        out.append(s[pos:m.start()])
        off.extend(range(pos, m.start()))
        for c, at in chars:
            out.append(c)
            off.append(m.start() + at)
        pos = m.end()
    if not pos:
        return s, None
    out.append(s[pos:])
    off.extend(range(pos, len(s) + 1))
    return "".join(out), off


def canon_map(s: str):
    """s with every escape decoded, again until none is left (an HTML page's own escaping, percent escapes,
    HTML entities, JSON escapes), and the offsets as in _decode (None: s is unchanged)."""
    off = None
    while True:
        d, o = _decode(s, _ANY_ESC)
        if o is None:
            return s, off
        off = o if off is None else [off[k] for k in o]
        s = d


def canon(s: str) -> str:
    return canon_map(s)[0]


def _lift(spans, off, shift):
    """Spans of a decoded string as spans of the string it was decoded from, which starts at `shift`."""
    if off is None:
        return [(shift + a, shift + b, rep) for a, b, rep in spans]
    return [(shift + off[a], shift + off[b], rep) for a, b, rep in spans]


def _merge(text, spans):
    """Spans sorted, without duplicates; one inside another is dropped, two that overlap become one."""
    out = []
    for a, b, rep in sorted(spans, key=lambda s: (s[0], -s[1])):
        if out and (a < out[-1][1] or (a, b) == out[-1][:2]):
            pa, pb, prep = out[-1]
            if b > pb:
                cut = prep.startswith(_CUT) or rep.startswith(_CUT)
                out[-1] = (pa, b, (mask_cut if cut else mask)(text[pa:b]))
            continue
        out.append((a, b, rep))
    return out


def apply_spans(text: str, spans, end: int | None = None) -> str:
    """text with each span replaced by what it says to show; with `end`, only text[:end] is shown (a span
    that starts before end is replaced whole)."""
    end = len(text) if end is None else end
    out, pos = [], 0
    for a, b, rep in spans:
        if a >= end:
            break
        out += [text[pos:a], rep]
        pos = b
    out.append(text[pos:end] if pos < end else "")
    return "".join(out)


_DQ = re.compile(r'"(?:[^"\\\r\n]|\\.)*"', re.S)
_SQ = re.compile(r"'[^'\r\n]*'")
_BRACKET = re.compile(r'"(?:[^"\\\r\n]|\\.)*"|[{}\[\]]', re.S)


def _bracket_end(s, i):
    """The end of the JSON object or array that starts at s[i], None when it does not close."""
    depth = 0
    for m in _BRACKET.finditer(s, i):
        c = m[0]
        if c[0] != '"':
            depth += 1 if c in "{[" else -1
            if depth == 0:
                return m.end()
    return None


def _extent(s, v, stop_re):
    """(start, end, after) of the value that starts at s[v]: inside its quotes when it is quoted, a JSON object
    or array to its end, otherwise up to the next character stop_re finds (spaces at its end left out)."""
    n = len(s)
    if v < n and s[v] in "\"'":
        m = (_DQ if s[v] == '"' else _SQ).match(s, v)
        if m:
            return v + 1, m.end() - 1, m.end()
        v += 1                          # an opening quote alone: the value after it
    elif v < n and s[v] in "{[":
        e = _bracket_end(s, v)
        if e is not None:
            return v, e, e
    m = stop_re.search(s, v)
    e = b = m.start() if m else n
    while b > v and s[b - 1] in " \t":
        b -= 1
    return v, b, e


@functools.lru_cache(maxsize=None)
def _stops(seps, spaces):
    stop = seps + "\r\n" + (" \t" if spaces else "")
    cls = re.escape(stop)
    return stop, re.compile(f"[^{cls}=]*"), re.compile(f"[{cls}]")


def _fields(s, seps, spaces):
    """(name or None, start, end) of each field of s. Fields are separated by any character of seps and by line
    breaks, and also by spaces and tabs when `spaces`. A field with "=" is name=value (spaces around "="
    allowed) and start..end is its value, without the spaces or quotes around it; a field without "=" (or a
    token whose base64 padding "=" ends it) is a value with no name. A value in quotes, or a JSON
    object or array, runs to its end even when it holds a separator."""
    stop, name_re, stop_re = _stops(seps, spaces)
    n, i = len(s), 0
    while i < n:
        if s[i] in stop or s[i] in " \t":
            i += 1
            continue
        j = name_re.match(s, i).end()
        k = j
        while k < n and s[k] in " \t":
            k += 1
        if k < n and s[k] == "=" and s[i:j].strip():
            v = k + 1
            while v < n and s[v] in " \t":
                v += 1
            a, b, after = _extent(s, v, stop_re)
            if s[a:b].strip("=") or not is_sensitive("", s[i:b].strip()):
                yield s[i:j].strip(), a, b
                i = after
                continue
        a, b, after = _extent(s, i, stop_re)
        yield None, a, b
        i = max(after, i + 1)


_LAST_WORD = re.compile(r"[\w.-]+$")


def _field_spans(name, s, a, b, found, plus=False):
    """Spans in s[a:b], the value of a field called name (None: a value with no name). The value is judged
    as sent and decoded: hidden whole when is_sensitive(name, value) holds (also for the last word of a name
    such as "(sid"), otherwise examined by value_spans. plus: "+" stands for a space (query strings, forms)."""
    raw = s[a:b]
    if not raw:
        return []
    dec, off = _decode(raw, _URL_ESC)
    # as a query parser reads it (the query table): a "+" as sent is a space, "%2B" is a plus
    spaced = _decode(raw.replace("+", " "), _URL_ESC)[0] if plus and "+" in raw else dec
    name = _decode(name or "", _URL_ESC)[0]
    word = _LAST_WORD.search(name)
    if (is_sensitive(name, raw) or (off is not None and is_sensitive(name, dec))
            or (word and word[0] != name and is_sensitive(word[0]))):
        return [(a, b, hide(dec, found, raw, spaced))]
    core = dec.lstrip()
    if not name and off is None and not (core[:1] in ("{", "[") or _URL_START.match(core)):
        return []                       # a word: nothing more in it
    return _lift(value_spans(spaced, found), off, a)


def _pairs(s, seps, spaces, found, plus=False):
    return [span for name, a, b in _fields(s, seps, spaces) for span in _field_spans(name, s, a, b, found, plus)]


def value_spans(value: str, found: set | None = None) -> list:
    """Spans to hide in a header, query or form value, or in a string inside JSON, when the value is not
    hidden whole: JSON in it as _json_spans finds them; a URL (or path) as url_spans finds them; otherwise its
    name=value fields, separated by & ; , ? # spaces or line breaks, each judged by _field_spans."""
    core = value.lstrip()
    if core[:1] in ("{", "["):
        return _merge(value, _json_spans(value, found)[0])
    if _URL_START.match(core):
        return url_spans(value, found)
    return _merge(value, _pairs(value, _VALUE_SEPS, True, found))


def url_spans(url: str, found: set | None = None) -> list:
    """Spans to hide in a URL or a path: the values of its path's matrix parameters (/feed;sessionid=…), of its
    query (fields separated by &) and of its fragment (fields as in a header value). The plain segments of the
    path are not judged."""
    h = url.find("#")
    end = h if h >= 0 else len(url)
    q = url.find("?", 0, end)
    spans, pos = [], 0
    for segment in url[:q if q >= 0 else end].split("/"):
        semi = segment.find(";")
        if semi >= 0:
            spans += _lift(_pairs(segment[semi + 1:], ";", False, found), None, pos + semi + 1)
        pos += len(segment) + 1
    if q >= 0:
        spans += _lift(_pairs(url[q + 1:end], "&", False, found, plus=True), None, q + 1)
    if h >= 0:
        spans += _lift(_pairs(url[h + 1:], _VALUE_SEPS, True, found), None, h + 1)
    return _merge(url, spans)


# a complete string | a string left open at the end | punctuation | any other run (number, true, a word) | a
# quote alone. A string does not hold a line break (JSON writes it \n).
_JSON_TOKEN = re.compile(r'(?P<str>"(?:[^"\\\r\n]|\\.)*")|(?P<open>"(?:[^"\\\r\n]|\\.)*\\?\Z)|(?P<punct>[{}\[\]:,])'
                         r'|(?P<word>[^\s{}\[\]:,"]+)|(?P<q>")', re.S)
_SPACE = re.compile(r"\s*")
_NOT_AFTER_STRING = re.compile(r'[\w"{\[]')


def _json_tokens(text):
    """(kind, start, end) of the JSON tokens of text. A "string" followed by a letter, a digit, a quote or a
    bracket is not one (no JSON string is): its quote is a quote alone, and reading goes on after it, so that
    a stray quote in a text body does not put the rest of it out of step."""
    toks, pos, n = [], 0, len(text)
    while (pos := _SPACE.match(text, pos).end()) < n:
        m = _JSON_TOKEN.match(text, pos)
        if m["str"] and _NOT_AFTER_STRING.match(text, _SPACE.match(text, m.end()).end()):
            toks.append(("q", pos, pos + 1))
            pos += 1
            continue
        toks.append((m.lastgroup, pos, m.end()))
        pos = m.end()
    return toks


def _json_spans(text, found, cut=False):
    """(spans, strings) for JSON text, or text holding JSON. The value of a "name": value pair is hidden when
    is_sensitive(name, value) holds; an array or object under a sensitive name is hidden whole. Any other
    string is hidden when it has the shape of a token, and otherwise examined by value_spans (JSON, a URL or
    name=value text inside it). Names are never hidden. cut: the text was cut off, so a string or a value
    hidden whole that is left open at the end is not shown. strings: (start, end) of every string."""
    toks = _json_tokens(text)
    spans, strings = [], []

    def is_colon(k):
        return k < len(toks) and toks[k][0] == "punct" and text[toks[k][1]] == ":"

    def name_of(k):
        if k >= 2 and is_colon(k - 1) and toks[k - 2][0] == "str":
            return _decode(text[toks[k - 2][1] + 1:toks[k - 2][2] - 1], _JSON_ESC)[0]
        return ""

    i = 0
    while i < len(toks):
        kind, a, b = toks[i]
        if kind == "str" and is_colon(i + 1):
            strings.append((a, b))                  # a name
        elif kind in ("str", "open"):
            strings.append((a, b))
            raw = text[a + 1:b - 1 if kind == "str" else b]
            if kind == "open" and cut:
                spans.append((a + 1, b, mask_cut(raw)))
                break
            dec, off = _decode(raw, _JSON_ESC)
            if is_sensitive(name_of(i), dec):
                spans.append((a + 1, a + 1 + len(raw), hide(dec, found, raw)))
            else:
                spans += _lift(value_spans(dec, found), off, a + 1)
        elif kind == "punct" and text[a] in "{[" and is_sensitive(name_of(i)):
            depth, j = 0, None
            for k in range(i, len(toks)):
                if toks[k][0] == "punct" and text[toks[k][1]] in "{}[]":
                    depth += 1 if text[toks[k][1]] in "{[" else -1
                    if depth == 0:
                        j = k
                        break
            last = j if j is not None else len(toks) - 1
            for k in range(i, last + 1):            # what the hidden value holds is hidden too (found)
                t, ta, tb = toks[k]
                if t == "str" and not is_colon(k + 1):
                    hide(_decode(text[ta + 1:tb - 1], _JSON_ESC)[0], found)
                elif t == "word":
                    hide(text[ta:tb], found)
            end = toks[j][2] if j is not None else len(text)
            if j is None and cut:
                spans.append((a, end, mask_cut(text[a:end])))
                break
            spans.append((a, end, hide(text[a:end], found)))
            i = last
        elif kind == "word" and is_sensitive(name_of(i)):
            spans.append((a, b, hide(text[a:b], found)))
        i += 1
    return spans, strings


_TEXT_NAME = re.compile(r"(?<![\w.%-])([\w.%-]+)[ \t]*=(?!=)[ \t]*")
_TEXT_STOP = re.compile(r"""[\s&;,#"'<>(){}\[\]]""")
_TOKEN_RUN = re.compile(r"[A-Za-z0-9+/_.-]+=*")     # "=" only as the padding at the end of a base64 run


def _text_field_spans(text, strings, cut, found):
    """name=value fields in text, outside the JSON strings (those are examined whole): a name right before
    "=" (spaces around it allowed); the value in quotes, a JSON object or array, or up to a space or one of
    & ; , # quotes brackets."""
    spans, pos, n = [], 0, len(text)
    starts = [a for a, _ in strings]
    while m := _TEXT_NAME.search(text, pos):
        k = bisect.bisect_right(starts, m.start()) - 1
        if k >= 0 and m.start() < strings[k][1]:
            pos = strings[k][1]
            continue
        a, b, after = _extent(text, m.end(), _TEXT_STOP)
        if cut and b == n and b > a:
            spans.append((a, n, mask_cut(text[a:n])))
            break
        spans += _field_spans(m[1], text, a, b, found, plus=True)
        pos = max(after, m.end())
    return spans


def _word_spans(text, strings, cut, found):
    """Runs of token characters outside the JSON strings (those are examined whole): one of the shape of a
    token is hidden, whatever stands around it (a value with no name). cut: a last run that reaches the end
    cannot be judged, so it is not shown."""
    spans, starts = [], [a for a, _ in strings]
    for m in _TOKEN_RUN.finditer(text):
        a, b = m.span()
        k = bisect.bisect_right(starts, a) - 1
        if k >= 0 and a < strings[k][1]:
            continue
        if cut and b == len(text):
            spans.append((a, b, mask_cut(m[0])))
        elif b - a >= 18 and is_sensitive("", run := m[0].rstrip(".")):
            spans.append((a, a + len(run), hide(run, found)))
    return spans


_BOUNDARY = re.compile(r"(?im)^--([^\r\n]{1,200}?)[ \t]*\r?\n(?=content-disposition:)")
_PART_NAME = re.compile(r'(?i)\bname[ \t]*=[ \t]*(?:"([^"]*)"|([^;\s]+))')
_BLANK_LINE = re.compile(r"\r?\n\r?\n")


def _multipart_spans(text, cut, found):
    """Spans in a multipart/form-data body, field by field (None when text is not one): the boundary is the
    first line "--…" followed by a Content-Disposition line; a field's value is hidden when is_sensitive(its
    name, value) holds and otherwise examined as a text body. cut: a last field without its closing boundary is
    not shown."""
    m = _BOUNDARY.search(text)
    if not m:
        return None
    delims = list(re.finditer(r"(?m)^--" + re.escape(m[1]) + r"(--)?[ \t]*(?:\r?\n|\Z)", text))
    spans = []
    for k, d in enumerate(delims):
        if d[1]:
            break                       # the closing boundary
        end = delims[k + 1].start() if k + 1 < len(delims) else len(text)
        if k + 1 < len(delims):         # the line break before the next boundary is not part of the value
            end -= 2 if text[end - 2:end] == "\r\n" else 1
        blank = _BLANK_LINE.search(text, d.end(), max(end, d.end()))
        if not blank:
            continue
        name = _PART_NAME.search(text, d.end(), blank.start())
        name = (name[1] if name[1] is not None else name[2]) if name else ""
        a, value = blank.end(), text[blank.end():end]
        if not value:
            continue
        if cut and k + 1 == len(delims):
            spans.append((a, end, mask_cut(value)))
        elif is_sensitive(name, value):
            spans.append((a, end, hide(value, found)))
        else:
            spans += _lift(text_spans(value, False, found), None, a)
    return spans


def text_spans(text: str, cut: bool = False, found: set | None = None) -> list:
    """Spans to hide in a JSON or text body: a multipart/form-data body field by field; otherwise "name": value
    pairs and strings as _json_spans finds them, name=value fields elsewhere in the text, and words of the
    shape of a token. Other words are not examined. cut: as in _json_spans."""
    spans = _multipart_spans(text, cut, found)
    if spans is None:
        spans, strings = _json_spans(text, found, cut)
        spans += _text_field_spans(text, strings, cut, found) + _word_spans(text, strings, cut, found)
    return _merge(text, spans)


def form_spans(text: str, cut: bool = False, found: set | None = None) -> list:
    """Spans to hide in a form body: fields separated by & or line breaks, each judged by _field_spans (JSON
    sent as a form is a value with no name, examined as JSON). cut: a last value that runs to the end is not
    shown."""
    spans = []
    for name, a, b in _fields(text, "&", False):
        if cut and b == len(text) and b > a:
            spans.append((a, b, mask_cut(text[a:b])))
        else:
            spans += _field_spans(name, text, a, b, found, plus=True)
    return _merge(text, spans)


def body_spans(text: str, kind: str, cut: bool = False, found: set | None = None) -> list:
    return (form_spans if kind == "form" else text_spans)(text, cut, found)


def note_parts(name: str, value: str, found: set | None) -> None:
    """For a header hidden whole (Cookie, Authorization, …): note in found what it holds as well, the value of
    each of its fields (a cookie's value, the credential after a word such as Bearer), so that their other
    occurrences are hidden too. Of Set-Cookie only the cookie itself, not its attributes (Path, Expires, …)."""
    if found is None:
        return
    if name.lower() == "set-cookie":
        value = value.split(";")[0]
    for _, a, b in _fields(value, _VALUE_SEPS, True):
        hide(_decode(value[a:b], _URL_ESC)[0], found, value[a:b])
    value_spans(value, found)


def mask_value(value: str, found: set | None = None) -> str:
    return apply_spans(value, value_spans(value, found))


def mask_path(path: str, found: set | None = None) -> str:
    return apply_spans(path, url_spans(path, found))


def mask_json(text: str, cut: bool = True, found: set | None = None) -> str:
    return apply_spans(text, _merge(text, _json_spans(text, found, cut)[0]))


def mask_text(text: str, cut: bool = False, found: set | None = None) -> str:
    return apply_spans(text, text_spans(text, cut, found))


def mask_form(text: str, cut: bool = False, found: set | None = None) -> str:
    return apply_spans(text, form_spans(text, cut, found))


def decode_content(raw: bytes, content_encoding) -> tuple[bytes, bool]:
    """Undo Content-Encoding. Returns (bytes, decoded). gzip and deflate are decoded;
    anything else (br, zstd: not in the standard library) and damaged or cut-off data
    come back unchanged with decoded False. No encoding: (raw, True)."""
    enc = (content_encoding or "").strip().lower()
    if enc in ("", "identity"):
        return raw, True
    try:
        if enc in ("gzip", "x-gzip"):
            return zlib.decompress(raw, 16 + zlib.MAX_WBITS), True
        if enc == "deflate":
            try:
                return zlib.decompress(raw), True
            except zlib.error:
                return zlib.decompress(raw, -zlib.MAX_WBITS), True
    except zlib.error:
        pass
    return raw, False


def _gunzip_verified(raw: bytes):
    """The content of one gzip member that fills `raw` exactly, or None. zlib checks the member's
    CRC-32 and length, so a result is gzip data beyond doubt, whatever the headers said."""
    if raw[:2] != b"\x1f\x8b":
        return None
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        data = d.decompress(raw) + d.flush()
    except zlib.error:
        return None
    return data if d.eof and not d.unused_data else None


def _charset(content_type):
    m = re.search(r"(?i)charset=\"?([A-Za-z0-9._-]+)", content_type or "")
    return m.group(1) if m else "utf-8"


def make_body(raw: bytes, content_type=None, content_encoding=None, encoding_known=True) -> dict | None:
    """Describe a request or response body. None for an empty body.

    encoding_known False: the Content-Encoding header could not be read (an HTTP/2 header block
    whose fields were not all restored); content_encoding is then ignored. Such a body is
    decompressed only when it is a complete gzip member whose checksum holds.

    {"size": bytes as sent, "sha256": of the bytes as sent,
     "encoding": Content-Encoding, or "gzip" when recognised from the bytes, else None,
     "encoding_detected": the encoding was recognised from the bytes, not read from a header,
     "decoded": the encoding was removed (True when there was none). False with encoding None:
                encoding_known was False and the bytes are neither gzip nor text, so they may be
                compressed in a way that cannot be told,
     "kind": "json" | "form" | "text" | "binary",
     "text": str for json/form/text (at most BODY_TEXT_MAX characters) else None,
     "truncated": the text was cut at BODY_TEXT_MAX,
     "preview_hex": first PREVIEW_BYTES of a binary body (after decoding when decoded) else None}
    """
    if not raw:
        return None
    detected = False
    if encoding_known:
        data, decoded = decode_content(raw, content_encoding)
        encoding = (content_encoding or "").strip().lower() or None
    else:
        data, decoded, encoding = raw, True, None
        unzipped = _gunzip_verified(raw)
        if unzipped is not None:
            data, encoding, detected = unzipped, "gzip", True
    ctype = (content_type or "").split(";")[0].strip().lower()
    text = None
    if decoded:
        try:
            text = data.decode(_charset(content_type))
        except (UnicodeDecodeError, LookupError):
            text = None
        # control characters other than whitespace: not text, whatever the declared type says
        if text is not None and re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", text):
            text = None
    if text is None:
        kind = "binary"
        if not encoding_known and not detected:
            decoded = False
    elif ctype == "application/x-www-form-urlencoded":
        kind = "form"
    elif ctype.endswith("json"):
        kind = "json"
    else:
        kind = "text"
        if text.lstrip()[:1] in ("{", "["):
            try:
                json.loads(text)
                kind = "json"
            except ValueError:
                pass
    return {
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "encoding": encoding,
        "encoding_detected": detected,
        "decoded": decoded,
        "kind": kind,
        "text": text[:BODY_TEXT_MAX] if text is not None else None,
        "truncated": text is not None and len(text) > BODY_TEXT_MAX,
        "preview_hex": data[:PREVIEW_BYTES].hex() if text is None else None,
    }


def header(headers, name: str):
    """First value of a header in a [[name, value], ...] list, case-insensitive; None if absent."""
    name = name.lower()
    for k, v in headers or []:
        if k.lower() == name:
            return v
    return None
