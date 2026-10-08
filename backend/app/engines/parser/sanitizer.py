from html.parser import HTMLParser


_VOID_TAGS = {"br", "hr"}
_ALLOWED_TAGS = {
    "p",
    "br",
    "div",
    "span",
    "b",
    "strong",
    "i",
    "em",
    "ul",
    "ol",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "table",
    "thead",
    "tbody",
    "tr",
    "td",
    "th",
    "blockquote",
    "pre",
    "code",
}
_SKIP_CONTENT_TAGS = {"script", "style", "iframe", "object", "embed", "noscript"}


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP_CONTENT_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        attr_map = {name.lower(): (value or "") for name, value in attrs}
        if tag == "br":
            self._parts.append("\n")
        elif tag == "a":
            href = attr_map.get("href", "").strip()
            if href and not href.lower().startswith(("javascript:", "data:", "vbscript:")):
                self._parts.append(f" {href} ")
        elif tag == "img":
            alt = attr_map.get("alt", "").strip()
            if alt:
                self._parts.append(f" {alt} ")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_CONTENT_TAGS and self._skip_depth:
            self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag in {"p", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote"}:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self._parts.append(data)

    def get_text(self) -> str:
        text = "".join(self._parts)
        lines = [line.strip() for line in text.splitlines()]
        return "\n".join(line for line in lines if line)


class _SafeHTMLFilter(HTMLParser):
    """Keep a small tag whitelist and drop scripts, handlers, and remote resources."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._out: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP_CONTENT_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth or tag not in _ALLOWED_TAGS:
            return
        if tag in _VOID_TAGS:
            self._out.append(f"<{tag}>")
        else:
            self._out.append(f"<{tag}>")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_CONTENT_TAGS and self._skip_depth:
            self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag in _ALLOWED_TAGS and tag not in _VOID_TAGS:
            self._out.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self._out.append(
            data.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )

    def get_html(self) -> str:
        return "".join(self._out)


def html_to_text(html: str) -> str:
    if not html:
        return ""
    parser = _HTMLTextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return ""
    return parser.get_text()


def sanitize_html(html: str) -> str:
    if not html:
        return ""
    parser = _SafeHTMLFilter()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return ""
    return parser.get_html()
