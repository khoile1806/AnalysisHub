"""Email analysis for the malware sidecar (.msg from Outlook, .eml/MIME).

Phishing is where most incidents start, so the mail itself is evidence: the
Received chain says where it really came from, SPF/DKIM/DMARC say whether the
sender domain was authorised, and the attachments are the actual payload —
which the backend re-submits into the normal malware pipeline as child samples.

Nothing is rendered or executed: the message is parsed as bytes, URLs are
defanged, and attachment bodies are returned base64-encoded for the caller.
"""
import base64
import email
import email.policy
import hashlib
import os
import re
import tempfile
from email.parser import BytesParser

MAX_ATTACHMENTS = 25
# Attachments travel back inside the JSON response as base64, which inflates them
# by ~37%. These caps are sized against the caller's response-read limit (see
# Emulator.postSample): exceed it and the JSON is truncated mid-document, which
# fails the WHOLE message parse rather than just dropping one big attachment.
MAX_ATTACHMENT_BYTES = int(os.environ.get("MAIL_MAX_ATTACHMENT", str(32 * 1024 * 1024)))
MAX_ATTACHMENT_TOTAL = int(os.environ.get("MAIL_MAX_ATTACHMENT_TOTAL", str(96 * 1024 * 1024)))
BODY_PREVIEW = 8000

RE_URL = re.compile(r"""(?:hxxps?|https?|ftp)://[^\s<>"'\)\]}]{4,2048}""", re.I)
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# Attachment extensions that should never arrive by mail in normal operations.
DANGEROUS_EXT = (".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".js", ".jse",
                 ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".lnk", ".ps1", ".msi",
                 ".msc", ".jar", ".reg", ".iso", ".img", ".vhd", ".vhdx", ".chm",
                 ".one", ".appx", ".appxbundle", ".diagcab", ".cpl", ".dll", ".pyz")
# Containers commonly used to smuggle the above past the mail gateway.
CONTAINER_EXT = (".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".arj", ".ace")
# URL shorteners hide the real destination.
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id")
# Free/consumer mail providers used as the reply channel of a BEC lure.
FREEMAIL = ("gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "protonmail.com",
            "proton.me", "mail.ru", "yandex.ru", "gmx.com", "aol.com", "zoho.com")


def defang(u):
    return u.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]", 1) \
        if u.lower().startswith(("http://", "https://")) else u


def _domain_of(addr):
    m = RE_EMAIL.search(addr or "")
    return m.group(0).rsplit("@", 1)[1].lower() if m else ""


def _registrable(domain):
    """Crude eTLD+1 — enough to compare 'mail.contoso.com' with 'contoso.com'."""
    parts = (domain or "").split(".")
    if len(parts) <= 2:
        return domain or ""
    if parts[-2] in ("co", "com", "org", "net", "gov", "edu", "ac") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _parse_received(headers):
    """Turn the Received chain into readable hops (newest first, as received)."""
    hops = []
    for raw in headers:
        line = " ".join(str(raw).split())
        frm = re.search(r"from\s+([^\s;]+)(?:\s+\(([^)]*)\))?", line, re.I)
        by = re.search(r"\bby\s+([^\s;]+)", line, re.I)
        ts = line.rsplit(";", 1)[-1].strip() if ";" in line else ""
        ips = RE_IP.findall(line)
        hops.append({
            "from": (frm.group(1) if frm else "")[:200],
            "from_detail": (frm.group(2) if frm and frm.group(2) else "")[:200],
            "by": (by.group(1) if by else "")[:200],
            "ip": ips[0] if ips else "",
            "date": ts[:100],
        })
        if len(hops) >= 30:
            break
    return hops


def _auth_results(msg):
    """SPF / DKIM / DMARC verdicts from Authentication-Results + legacy headers."""
    out = {}
    blob = " ".join(str(v) for k, v in msg.items()
                    if k.lower() in ("authentication-results", "arc-authentication-results",
                                     "received-spf", "x-forefront-antispam-report",
                                     "dkim-signature", "x-ms-exchange-authentication-results"))
    for mech in ("spf", "dkim", "dmarc", "compauth"):
        m = re.search(mech + r"=([a-z]+)", blob, re.I)
        if m:
            out[mech] = m.group(1).lower()
    if "spf" not in out:
        m = re.search(r"received-spf:\s*(\w+)", blob, re.I)
        if m:
            out["spf"] = m.group(1).lower()
    if blob and "dkim-signature" in blob.lower() and "dkim" not in out:
        out["dkim"] = "present (unverified)"
    return out


def _collect_urls(text):
    urls, seen = [], set()
    for u in RE_URL.findall(text or ""):
        u = u.rstrip(".,;)")
        key = u.lower()
        if key in seen:
            continue
        seen.add(key)
        urls.append(u[:2000])
        if len(urls) >= 200:
            break
    return urls


def _qr_codes(blob):
    """Decode QR codes in an attached image — 'quishing' moves the payload URL
    into a picture precisely to get past URL scanning."""
    try:
        import io
        from PIL import Image
        from pyzbar.pyzbar import decode as zbar_decode
    except Exception:
        return []
    try:
        img = Image.open(io.BytesIO(blob))
        return [d.data.decode("utf-8", "ignore")[:2000] for d in zbar_decode(img)][:10]
    except Exception:
        return []


def _body_parts(msg):
    """Return (text_body, html_body) walking the MIME tree."""
    text, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp.lower():
                continue
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                continue
            body = payload.decode(part.get_content_charset() or "utf-8", "ignore")
            if part.get_content_type() == "text/plain" and not text:
                text = body
            elif part.get_content_type() == "text/html" and not html:
                html = body
    else:
        try:
            payload = msg.get_payload(decode=True) or b""
            body = payload.decode(msg.get_content_charset() or "utf-8", "ignore")
        except Exception:
            body = ""
        if msg.get_content_type() == "text/html":
            html = body
        else:
            text = body
    return text, html


def _attachment(name, blob, budget=None):
    """One attachment. `budget` is a single-element list carrying the remaining
    bytes that may still be base64-forwarded across all attachments; when it runs
    out the metadata is still returned but the content is not, so one huge file
    cannot truncate the response and fail the whole message parse."""
    ext = os.path.splitext(name or "")[1].lower()
    entry = {
        "name": (name or "attachment.bin")[:300],
        "size": len(blob),
        "md5": hashlib.md5(blob).hexdigest(),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "ext": ext,
        "dangerous": ext in DANGEROUS_EXT,
        "container": ext in CONTAINER_EXT,
    }
    if blob[:4] in (b"\x89PNG", b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1") or ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp"):
        qr = _qr_codes(blob)
        if qr:
            entry["qr_codes"] = qr
    room = budget[0] if budget is not None else MAX_ATTACHMENT_TOTAL
    if len(blob) <= MAX_ATTACHMENT_BYTES and len(blob) <= room:
        entry["content_b64"] = base64.b64encode(blob).decode("ascii")
        if budget is not None:
            budget[0] -= len(blob)
    else:
        entry["note"] = ("attachment not forwarded for analysis (%d bytes; per-file limit %d, "
                         "remaining transfer budget %d) — download it from the message to analyse it separately"
                         % (len(blob), MAX_ATTACHMENT_BYTES, room))
    return entry


def _parse_eml(data):
    msg = BytesParser(policy=email.policy.default).parsebytes(data)
    headers = {}
    for k in ("From", "To", "Cc", "Subject", "Date", "Reply-To", "Return-Path",
              "Message-ID", "X-Mailer", "User-Agent", "X-Originating-IP",
              "X-Sender-IP", "Sender", "List-Unsubscribe", "Content-Language"):
        v = msg.get(k)
        if v:
            headers[k] = str(v)[:500]
    text, html = _body_parts(msg)
    attachments = []
    budget = [MAX_ATTACHMENT_TOTAL]  # shared across this message's attachments
    for part in msg.walk() if msg.is_multipart() else []:
        disp = str(part.get("Content-Disposition") or "")
        fname = part.get_filename()
        if "attachment" not in disp.lower() and not fname:
            continue
        try:
            blob = part.get_payload(decode=True) or b""
        except Exception:
            continue
        if not blob:
            continue
        attachments.append(_attachment(fname or "attachment.bin", blob, budget))
        if len(attachments) >= MAX_ATTACHMENTS:
            break
    return {
        "format": "eml",
        "headers": headers,
        "received_chain": _parse_received(msg.get_all("Received") or []),
        "auth_results": _auth_results(msg),
        "body_text": text[:BODY_PREVIEW],
        "body_html": html[:BODY_PREVIEW],
        "attachments": attachments,
        "_url_source": (text or "") + "\n" + (html or ""),
    }


def _parse_msg(data):
    """Outlook .msg (OLE compound file) via extract-msg."""
    try:
        import extract_msg
    except Exception as e:
        return {"format": "msg", "error": "extract-msg not installed: %s" % e}
    fd, path = tempfile.mkstemp(suffix=".msg")
    os.write(fd, data)
    os.close(fd)
    try:
        m = extract_msg.Message(path)
        headers = {}
        for key, val in (("From", m.sender), ("To", m.to), ("Cc", m.cc),
                         ("Subject", m.subject), ("Date", str(m.date or "")),
                         ("Message-ID", getattr(m, "messageId", "") or "")):
            if val:
                headers[key] = str(val)[:500]
        raw_hdr = ""
        try:
            raw_hdr = str(m.header or "")
        except Exception:
            pass
        received, auth = [], {}
        if raw_hdr:
            hdr_msg = email.message_from_string(raw_hdr, policy=email.policy.default)
            received = _parse_received(hdr_msg.get_all("Received") or [])
            auth = _auth_results(hdr_msg)
            for k in ("Reply-To", "Return-Path", "X-Mailer", "X-Originating-IP", "Sender"):
                v = hdr_msg.get(k)
                if v and k not in headers:
                    headers[k] = str(v)[:500]
        body = ""
        try:
            body = m.body or ""
        except Exception:
            pass
        html = ""
        try:
            raw_html = m.htmlBody
            if raw_html:
                html = raw_html.decode("utf-8", "ignore") if isinstance(raw_html, bytes) else str(raw_html)
        except Exception:
            pass
        attachments = []
        budget = [MAX_ATTACHMENT_TOTAL]  # shared across this message's attachments
        for att in (m.attachments or [])[:MAX_ATTACHMENTS]:
            try:
                blob = att.data
                if isinstance(blob, str):
                    blob = blob.encode("utf-8", "ignore")
                # A nested .msg attachment comes back as a Message object.
                if not isinstance(blob, (bytes, bytearray)):
                    continue
                name = att.longFilename or att.shortFilename or "attachment.bin"
                attachments.append(_attachment(str(name), bytes(blob), budget))
            except Exception:
                continue
        return {
            "format": "msg",
            "headers": headers,
            "received_chain": received,
            "auth_results": auth,
            "body_text": body[:BODY_PREVIEW],
            "body_html": html[:BODY_PREVIEW],
            "attachments": attachments,
            "_url_source": (body or "") + "\n" + (html or "") + "\n" + raw_hdr,
        }
    except Exception as e:
        return {"format": "msg", "error": str(e)}
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _assess(res):
    """Deterministic phishing indicators derived from the parsed message."""
    flags = []
    hdr = res.get("headers") or {}
    frm = hdr.get("From", "")
    from_dom = _domain_of(frm)
    reply_dom = _domain_of(hdr.get("Reply-To", ""))
    ret_dom = _domain_of(hdr.get("Return-Path", ""))

    auth = res.get("auth_results") or {}
    for mech in ("spf", "dkim", "dmarc"):
        v = auth.get(mech, "")
        if v in ("fail", "softfail", "permerror", "temperror", "none"):
            flags.append("%s=%s — sender domain authentication did not pass" % (mech.upper(), v))
    if not auth:
        flags.append("no SPF/DKIM/DMARC results present in the headers")

    if reply_dom and from_dom and _registrable(reply_dom) != _registrable(from_dom):
        flags.append("Reply-To domain (%s) differs from From domain (%s) — replies go to the attacker" % (reply_dom, from_dom))
    if ret_dom and from_dom and _registrable(ret_dom) != _registrable(from_dom):
        flags.append("Return-Path domain (%s) differs from From domain (%s) — envelope spoofing" % (ret_dom, from_dom))
    if reply_dom and reply_dom in FREEMAIL and from_dom and from_dom not in FREEMAIL:
        flags.append("Reply-To points at a free mail provider (%s) while From claims a corporate domain" % reply_dom)

    # Display name claims one organisation, the address belongs to another.
    disp = re.sub(r"<[^>]*>", "", frm).strip(' "')
    disp_dom = re.search(r"([A-Za-z0-9\-]+\.(?:com|net|org|vn|io|co))", disp or "", re.I)
    if disp_dom and from_dom and _registrable(disp_dom.group(1).lower()) != _registrable(from_dom):
        flags.append("display name claims %s but the address is @%s — display-name spoofing" % (disp_dom.group(1), from_dom))

    urls = res.get("urls") or []
    for u in urls:
        low = u.lower()
        host = re.sub(r"^\w+://", "", low).split("/")[0]
        if any(s in host for s in SHORTENERS):
            flags.append("URL shortener hides the real destination: %s" % u[:120])
            break
    if any(RE_IP.match(re.sub(r"^\w+://", "", u.lower()).split("/")[0] or "") for u in urls):
        flags.append("link points directly at an IP address instead of a hostname")
    if any("@" in re.sub(r"^\w+://", "", u).split("/")[0] for u in urls):
        flags.append("URL contains an embedded credential/@ trick that masks the real host")

    for att in res.get("attachments") or []:
        if att.get("dangerous"):
            flags.append("executable/script attachment: %s" % att["name"])
        if att.get("qr_codes"):
            flags.append("QR code embedded in an attached image (quishing): %s" % att["qr_codes"][0][:120])
    html = (res.get("body_html") or "").lower()
    if "<form" in html and ("password" in html or "signin" in html or "login" in html):
        flags.append("HTML body contains a credential-harvesting form")
    if "<script" in html:
        flags.append("HTML body contains inline JavaScript")
    if re.search(r"urgent|verify your account|password will expire|suspend|invoice attached|payment|wire transfer|khẩn|hóa đơn|thanh toán", res.get("body_text", "") + " " + hdr.get("Subject", ""), re.I):
        flags.append("social-engineering urgency/finance lure in the subject or body")
    return flags


def analyse(data, filename=""):
    name = (filename or "").lower()
    is_msg = name.endswith(".msg") or data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    res = _parse_msg(data) if is_msg else _parse_eml(data)
    if res.get("error") and is_msg:
        # An OLE file that is not really a .msg — try MIME as a fallback.
        alt = _parse_eml(data)
        if alt.get("headers"):
            res = alt
    blob = res.pop("_url_source", "")
    urls = _collect_urls(blob)
    for att in res.get("attachments") or []:
        for qr in att.get("qr_codes") or []:
            if qr not in urls:
                urls.append(qr)
    res["urls"] = urls[:200]
    res["defanged_urls"] = [defang(u) for u in urls[:200]]
    res["ips"] = sorted({ip for ip in RE_IP.findall(blob)})[:50]
    res["emails"] = sorted({e.lower() for e in RE_EMAIL.findall(blob)})[:50]
    res["sender_domain"] = _domain_of((res.get("headers") or {}).get("From", ""))
    res["flags"] = _assess(res)
    return res
