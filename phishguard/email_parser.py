import hashlib
import ipaddress
import os
import re
from email import policy
from email.parser import BytesParser
from email.message import Message
from html.parser import HTMLParser

from phishguard.security import (
    EmailLimitError,
    MAX_ATTACHMENTS,
    MAX_BODY_CHARS,
    MAX_EMAIL_BYTES,
    MAX_HEADER_BYTES,
    MAX_MIME_PARTS,
    MAX_URLS,
)


def parse_eml(file_path: str) -> dict:
    """
    Parse a .eml file and extract all relevant fields for phishing analysis.
    Returns a dict with headers, body text, URLs, IPs, and attachments.
    """
    _validate_email_file(file_path)

    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    part_count = sum(1 for _ in msg.walk())
    if part_count > MAX_MIME_PARTS:
        raise EmailLimitError(
            f"Email contains {part_count} MIME parts; the limit is {MAX_MIME_PARTS}."
        )

    body_text, body_html = _get_bodies(msg)
    html_links = _extract_html_links(body_html)

    result: dict = {
        "subject":          msg.get("Subject", ""),
        "from":             msg.get("From", ""),
        "reply_to":         msg.get("Reply-To", ""),
        "to":               msg.get("To", ""),
        "date":             msg.get("Date", ""),
        "message_id":       msg.get("Message-ID", ""),
        "x_originating_ip": msg.get("X-Originating-IP", ""),
        "received_chain":   _extract_received_chain(msg),
        "spf":              msg.get("Received-SPF", ""),
        "dkim":             msg.get("DKIM-Signature", ""),
        "dmarc":            msg.get("Authentication-Results", ""),
        "authentication_results": msg.get_all("Authentication-Results", []),
        # Mailing-list (RFC 2919/2369) and resent (RFC 5322) headers. A list
        # that rewrites a message legitimately breaks its DKIM signature, so
        # the analyzer uses these to soften authentication-failure scoring.
        "list_id":          msg.get("List-Id", ""),
        "list_post":        msg.get("List-Post", ""),
        "list_unsubscribe": msg.get("List-Unsubscribe", ""),
        "resent_from":      msg.get("Resent-From", ""),
        "body_text":        body_text,
        "body_html":        body_html,
        "html_links":       html_links,
        "urls":             [],
        "ips":              [],
        "attachments":      [],
    }

    result["urls"] = _merge_urls(
        _extract_urls(result["body_text"]),
        [link["href"] for link in html_links],
    )
    result["ips"]  = _extract_ips(" ".join(result["received_chain"]) + " " + result["x_originating_ip"])
    result["attachments"] = _extract_attachments(msg)

    return result


def _validate_email_file(file_path: str) -> None:
    """Reject oversized messages and headers before MIME parsing begins."""
    size_bytes = os.path.getsize(file_path)
    if size_bytes > MAX_EMAIL_BYTES:
        raise EmailLimitError(
            f"Email is {size_bytes} bytes; the limit is {MAX_EMAIL_BYTES} bytes."
        )

    with open(file_path, "rb") as message_file:
        header_preview = message_file.read(MAX_HEADER_BYTES + 4)

    header_endings = (header_preview.find(b"\r\n\r\n"), header_preview.find(b"\n\n"))
    if all(index == -1 for index in header_endings):
        raise EmailLimitError(
            f"Email headers exceed {MAX_HEADER_BYTES} bytes or are malformed."
        )


def _extract_received_chain(msg: Message) -> list[str]:
    """Extract all Received headers in order (oldest last)."""
    return msg.get_all("Received", [])


def _get_bodies(msg: Message) -> tuple[str, str]:
    """Extract bounded plain-text and HTML bodies without rendering content."""
    plain_parts: list[str] = []
    html_parts: list[str] = []
    message_parts = msg.walk() if msg.is_multipart() else (msg,)
    body_length = 0
    for part in message_parts:
        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue
        try:
            part_text = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            part_text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")

        body_length += len(part_text)
        if body_length > MAX_BODY_CHARS:
            raise EmailLimitError(
                f"Extracted plain-text body and HTML body content exceed the "
                f"{MAX_BODY_CHARS}-character limit."
            )
        if content_type == "text/plain":
            plain_parts.append(part_text)
        else:
            html_parts.append(part_text)

    return "".join(plain_parts), "".join(html_parts)


class _SafeHTMLLinkParser(HTMLParser):
    """Collect anchor destinations and visible text without rendering HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict] = []
        self._active_href: str | None = None
        self._active_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a" or self._active_href is not None:
            return
        attributes = {name.lower(): value for name, value in attrs}
        href = (attributes.get("href") or "").strip()
        if re.match(r"^https?://", href, re.IGNORECASE):
            self._active_href = href
            self._active_text = []

    def handle_data(self, data: str) -> None:
        if self._active_href is not None:
            self._active_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or self._active_href is None:
            return
        if len(self.links) >= MAX_URLS:
            raise EmailLimitError(f"Email contains more than {MAX_URLS} HTML links.")
        displayed_text = " ".join("".join(self._active_text).split())
        self.links.append({
            "href": self._active_href,
            "displayed_text": displayed_text,
        })
        self._active_href = None
        self._active_text = []

    def close(self) -> None:
        super().close()
        if self._active_href is not None:
            self.handle_endtag("a")


def _extract_html_links(html_body: str) -> list[dict]:
    """Extract bounded HTTP(S) anchor evidence from HTML source."""
    if not html_body:
        return []
    parser = _SafeHTMLLinkParser()
    try:
        parser.feed(html_body)
        parser.close()
    except EmailLimitError:
        raise
    except (ValueError, AssertionError):
        return parser.links
    return parser.links


def _merge_urls(*url_groups: list[str]) -> list[str]:
    """Merge URL sources in order while enforcing the global unique-URL limit."""
    urls: list[str] = []
    seen_urls: set[str] = set()
    for group in url_groups:
        for url in group:
            if url in seen_urls:
                continue
            if len(urls) >= MAX_URLS:
                raise EmailLimitError(f"Email contains more than {MAX_URLS} unique URLs.")
            seen_urls.add(url)
            urls.append(url)
    return urls


_TRAILING_URL_PUNCTUATION = ".,;:!?'*"


def _trim_trailing_punctuation(url: str) -> str:
    """Drop sentence punctuation that the URL regex swallows from prose.

    "Log in (https://paypal.com/login)." must yield the URL without ")." so
    IOCs and reputation lookups use the real destination. A closing
    parenthesis is kept when it balances one inside the URL, as in
    https://en.wikipedia.org/wiki/Phishing_(security).
    """
    while url:
        if url[-1] in _TRAILING_URL_PUNCTUATION:
            url = url[:-1]
        elif url[-1] == ")" and url.count(")") > url.count("("):
            url = url[:-1]
        else:
            break
    return url


def _extract_urls(text: str) -> list[str]:
    """Extract unique URLs from a block of text, preserving their appearance order."""
    url_pattern = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+',
        re.IGNORECASE
    )
    urls: list[str] = []
    seen_urls: set[str] = set()
    for match in url_pattern.finditer(text):
        url = _trim_trailing_punctuation(match.group(0))
        if url in seen_urls:
            continue
        if len(urls) >= MAX_URLS:
            raise EmailLimitError(f"Email contains more than {MAX_URLS} unique URLs.")
        seen_urls.add(url)
        urls.append(url)
    return urls


def _is_private_ip(ip: str) -> bool:
    """
    Return True if the IP is in a private or loopback range.
    Correctly handles RFC 1918 ranges:
      - 10.0.0.0/8
      - 172.16.0.0/12  (172.16.x.x through 172.31.x.x only)
      - 192.168.0.0/16
      - 127.0.0.0/8 (loopback)
    """
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return True


def _extract_ips(text: str) -> list[str]:
    """Extract unique public IPv4 addresses, preserving their appearance order."""
    ip_pattern = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )
    all_ips = dict.fromkeys(ip_pattern.findall(text))
    return [ip for ip in all_ips if not _is_private_ip(ip)]


# Leading bytes that identify a file's real format. Matched at offset 0 only,
# longest first so a specific signature wins over a shorter prefix of it.
#
# These are deliberately few. The goal is not to be `libmagic`, it is to catch
# the one case that matters for phishing triage: a payload whose real format
# contradicts the extension it is advertising.
_FILE_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2_compound"),
    (b"7z\xbc\xaf\x27\x1c", "7z_archive"),
    (b"Rar!\x1a\x07", "rar_archive"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\x7fELF", "elf_executable"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip_container"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"{\\rtf", "rtf"),
    (b"\xca\xfe\xba\xbe", "java_class"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x1f\x8b", "gzip_archive"),
    (b"MZ", "pe_executable"),
    (b"#!", "script_shebang"),
)

# Formats that run code when opened. A payload detected as one of these while
# claiming a document extension is the signal worth escalating on.
EXECUTABLE_SIGNATURES = frozenset({
    "pe_executable", "elf_executable", "java_class", "script_shebang",
})

# What each extension's bytes should look like. Extensions absent from this
# map are not checked: "no expectation" must not read as "mismatch".
EXPECTED_SIGNATURES: dict[str, frozenset[str]] = {
    ".pdf": frozenset({"pdf"}),
    ".rtf": frozenset({"rtf"}),
    ".png": frozenset({"png"}),
    ".gif": frozenset({"gif"}),
    ".jpg": frozenset({"jpeg"}),
    ".jpeg": frozenset({"jpeg"}),
    # Legacy Office and MSI are OLE2 compound documents.
    ".doc": frozenset({"ole2_compound"}),
    ".xls": frozenset({"ole2_compound"}),
    ".ppt": frozenset({"ole2_compound"}),
    ".msi": frozenset({"ole2_compound"}),
    # OOXML and its macro-enabled variants are ZIP containers, as are JAR/APK.
    ".docx": frozenset({"zip_container"}),
    ".xlsx": frozenset({"zip_container"}),
    ".pptx": frozenset({"zip_container"}),
    ".docm": frozenset({"zip_container"}),
    ".xlsm": frozenset({"zip_container"}),
    ".pptm": frozenset({"zip_container"}),
    ".zip": frozenset({"zip_container"}),
    ".jar": frozenset({"zip_container"}),
    ".apk": frozenset({"zip_container"}),
    ".rar": frozenset({"rar_archive"}),
    ".7z": frozenset({"7z_archive"}),
    ".gz": frozenset({"gzip_archive"}),
    ".exe": frozenset({"pe_executable"}),
    ".dll": frozenset({"pe_executable"}),
    ".scr": frozenset({"pe_executable"}),
    ".com": frozenset({"pe_executable"}),
}


def _detect_signature(payload: bytes) -> str:
    """Name the payload's real format from its leading bytes, or ""."""
    for magic, name in _FILE_SIGNATURES:
        if payload.startswith(magic):
            return name
    return ""


def _is_attachment_part(part: Message) -> bool:
    """Decide whether a MIME part carries a file rather than message body.

    ``Content-Disposition: attachment`` is not required. Mail that delivers
    malware routinely omits the header or sends ``inline``, and relying on it
    meant an executable arrived completely invisible — not scored, and not
    even listed as an indicator for the analyst.
    """
    if part.get_content_maintype() == "multipart":
        return False
    if (part.get_content_disposition() or "").lower() == "attachment":
        return True
    # A named part is a file whatever its disposition says. get_filename()
    # also reads the Content-Type "name" parameter, which is where a part
    # with no Content-Disposition at all still declares itself.
    if part.get_filename():
        return True
    # Anything else that is not message text: inline images, nested messages,
    # unnamed octet-streams.
    return part.get_content_type() not in ("text/plain", "text/html")


def _extract_attachments(msg: Message) -> list[dict]:
    """Extract attachment metadata, including SHA-256 and detected format."""
    attachments: list[dict] = []
    for part in msg.walk():
        if not _is_attachment_part(part):
            continue
        if len(attachments) >= MAX_ATTACHMENTS:
            raise EmailLimitError(
                f"Email contains more than {MAX_ATTACHMENTS} attachments."
            )
        payload = part.get_payload(decode=True) or b""
        attachments.append({
            "filename":     part.get_filename(""),
            "content_type": part.get_content_type(),
            "size_bytes":   len(payload),
            "disposition":  part.get_content_disposition() or "none",
            # SHA-256 lets an analyst pivot to a sandbox or reputation service
            # without ever opening the file.
            "sha256":       hashlib.sha256(payload).hexdigest(),
            "detected_type": _detect_signature(payload),
        })
    return attachments
