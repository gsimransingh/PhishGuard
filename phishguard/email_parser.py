import email
import re
from email import policy
from email.parser import BytesParser
from email.message import Message


def parse_eml(file_path: str) -> dict:
    """
    Parse a .eml file and extract all relevant fields for phishing analysis.
    Returns a dict with headers, body text, URLs, IPs, and attachments.
    """
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

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
        "body_text":        _get_body(msg),
        "urls":             [],
        "ips":              [],
        "attachments":      [],
    }

    result["urls"] = _extract_urls(result["body_text"])
    result["ips"]  = _extract_ips(" ".join(result["received_chain"]) + " " + result["x_originating_ip"])
    result["attachments"] = _extract_attachments(msg)

    return result


def _extract_received_chain(msg: Message) -> list[str]:
    """Extract all Received headers in order (oldest last)."""
    return msg.get_all("Received", [])


def _get_body(msg: Message) -> str:
    """Extract plain text body from the email."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_content()
                except Exception:
                    body += str(part.get_payload(decode=True))
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = str(msg.get_payload(decode=True))
    return body


def _extract_urls(text: str) -> list[str]:
    """Extract unique URLs from a block of text, preserving their appearance order."""
    url_pattern = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+',
        re.IGNORECASE
    )
    return list(dict.fromkeys(url_pattern.findall(text)))


def _is_private_ip(ip: str) -> bool:
    """
    Return True if the IP is in a private or loopback range.
    Correctly handles RFC 1918 ranges:
      - 10.0.0.0/8
      - 172.16.0.0/12  (172.16.x.x through 172.31.x.x only)
      - 192.168.0.0/16
      - 127.0.0.0/8 (loopback)
    """
    if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if re.match(r'^172\.(1[6-9]|2\d|3[01])\.', ip):
        return True
    return False


def _extract_ips(text: str) -> list[str]:
    """Extract unique public IPv4 addresses, preserving their appearance order."""
    ip_pattern = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )
    all_ips = dict.fromkeys(ip_pattern.findall(text))
    return [ip for ip in all_ips if not _is_private_ip(ip)]


def _extract_attachments(msg: Message) -> list[dict]:
    """Extract metadata of any attachments (filename, content-type, size)."""
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            attachments.append({
                "filename":     part.get_filename(""),
                "content_type": part.get_content_type(),
                "size_bytes":   len(part.get_payload(decode=True) or b"")
            })
    return attachments
