from __future__ import annotations

from email import message_from_bytes, policy
from email.headerregistry import AddressHeader
from email.message import Message
from email.utils import getaddresses

from app.engines.parser.exceptions import EmailParseError
from app.engines.parser.extractors import (
    collect_named_headers,
    collect_raw_headers,
    decode_header_value,
    extract_attachment_metadata,
    extract_urls,
    get_body_parts,
)
from app.engines.parser.sanitizer import html_to_text, sanitize_html

COMPAT_POLICY = policy.compat32


def parse_eml(raw: str | bytes) -> dict:
    data = _to_bytes(raw)
    if not data.strip():
        raise EmailParseError("Email content is empty.")

    try:
        message = message_from_bytes(data, policy=COMPAT_POLICY)
    except Exception as exc:
        raise EmailParseError("The email could not be parsed.") from exc




    if not isinstance(message, Message):
        raise EmailParseError("The email could not be parsed.")

    try:
        return _message_to_dict(message)
    except EmailParseError:
        raise
    except Exception as exc:
        raise EmailParseError("The email could not be parsed.") from exc


def _to_bytes(raw: str | bytes) -> bytes:
    if isinstance(raw, bytes):
        return raw
    if not isinstance(raw, str):
        raise EmailParseError("Email content must be text or bytes.")
    return raw.encode("utf-8", errors="replace")


def _message_to_dict(message: Message) -> dict:
    plain_text, html = get_body_parts(message)
    sanitized_from_html = html_to_text(html)
    sanitized_text = plain_text or sanitized_from_html
    if plain_text and sanitized_from_html and sanitized_from_html not in plain_text:
        sanitized_text = f"{plain_text}\n\n{sanitized_from_html}".strip()

    named = collect_named_headers(message)
    urls = extract_urls(plain_text, html, sanitized_text)

    return {
        "message": {
            "subject": decode_header_value(message, "Subject"),
            "from": _address_list(message, "From"),
            "to": _address_list(message, "To"),
            "cc": _address_list(message, "Cc"),
            "reply_to": _address_list(message, "Reply-To"),
            "return_path": decode_header_value(message, "Return-Path"),
            "date": decode_header_value(message, "Date"),
            "message_id": decode_header_value(message, "Message-ID"),
        },
        "headers": {
            "received": named["received"],
            "authentication_results": named["authentication_results"],
            "received_spf": named["received_spf"],
            "dkim_signature": named["dkim_signature"],
            "dmarc": named["dmarc"],
            "raw": collect_raw_headers(message),
        },
        "body": {
            "plain_text": plain_text,
            "html": html,
            "sanitized_text": sanitized_text,
            "sanitized_html": sanitize_html(html),
        },
        "urls": urls,
        "attachments": extract_attachment_metadata(message),
    }


def _address_list(message: Message, header_name: str) -> list[str]:
    values = message.get_all(header_name, [])
    if not values:
        return []
    formatted: list[str] = []
    for value in values:
        if isinstance(value, AddressHeader):
            formatted.extend(str(address) for address in value.addresses)
            continue
        pairs = getaddresses([str(value)])
        for display_name, addr in pairs:
            if display_name and addr:
                formatted.append(f"{display_name} <{addr}>")
            elif addr:
                formatted.append(addr)
            elif display_name:
                formatted.append(display_name)
    return formatted
