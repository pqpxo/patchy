"""Security news for the Overview: the newest posts from a few RSS or Atom feeds, fetched hourly by the worker.

Feed text is untrusted: titles are reduced to plain text, links must be https, and documents with a DOCTYPE
(where entity tricks live) are refused. The browser only ever sees the stored list, never the feeds.
"""
from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

import httpx
from sqlalchemy.orm import Session

from .config import settings
from .db import utcnow
from .models import AppSetting
from .vulns import USER_AGENT

KEEP = 5
MAX_BYTES = 2_000_000
ATOM = "{http://www.w3.org/2005/Atom}"


def feeds() -> list[str]:
    return [u for u in (s.strip() for s in settings.news_feeds.split(",")) if u.startswith("https://")]


def _text(s: str | None, limit: int = 300) -> str:
    s = html.unescape(re.sub(r"<[^>]*>", " ", html.unescape(s or "")))  # titles can be escaped HTML, sometimes twice
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit] + ("..." if len(s) > limit else "")


def _when(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = parsedate_to_datetime(s.strip())  # RSS: RFC 822
    except (TypeError, ValueError, IndexError):
        try:
            d = datetime.fromisoformat(s.strip().replace("Z", "+00:00"))  # Atom: RFC 3339
        except ValueError:
            return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)  # UTC, so ISO strings sort


def parse(data: bytes, url: str) -> list[dict]:
    if b"<!DOCTYPE" in data[:4096].upper() or b"<!ENTITY" in data.upper():
        raise ValueError("feed has a DOCTYPE")
    root = ET.fromstring(data)
    channel = root.find("channel")
    if channel is not None:  # RSS 2.0
        source = _text(channel.findtext("title"), 60)
        entries = [(i.findtext("title"), i.findtext("link"), i.findtext("pubDate")) for i in channel.iter("item")]
    else:  # Atom
        source = _text(root.findtext(f"{ATOM}title"), 60)
        entries = []
        for e in root.iter(f"{ATOM}entry"):
            links = e.findall(f"{ATOM}link")
            link = next((x.get("href") for x in links if x.get("rel", "alternate") == "alternate"), None)
            entries.append((e.findtext(f"{ATOM}title"), link,
                            e.findtext(f"{ATOM}published") or e.findtext(f"{ATOM}updated")))
    source = source or urlsplit(url).hostname or url
    out = []
    for title, link, when in entries:
        link, title, d = (link or "").strip(), _text(title), _when(when)
        if title and link.startswith("https://") and len(link) <= 1000:
            out.append({"title": title, "url": link, "source": source, "published": d.isoformat() if d else None})
    return out


def _get(client: httpx.Client, url: str) -> bytes:
    with client.stream("GET", url) as r:
        r.raise_for_status()
        if r.url.scheme != "https":
            raise ValueError("redirected away from https")
        data = bytearray()
        for chunk in r.iter_bytes():
            data += chunk
            if len(data) > MAX_BYTES:
                raise ValueError("feed too large")
        return bytes(data)


def http_client() -> httpx.Client:
    return httpx.Client(timeout=20, headers={"User-Agent": USER_AGENT}, follow_redirects=True, max_redirects=3)


def refresh(db: Session, client: httpx.Client | None = None) -> int:
    """Fetch every feed and keep the newest posts across them. A failing feed keeps the others' posts."""
    urls = feeds()
    if not urls:
        return 0
    items, errors = [], []
    with (client or http_client()) as c:
        for url in urls:
            try:
                items += parse(_get(c, url), url)
            except (httpx.HTTPError, ET.ParseError, ValueError) as e:
                status = getattr(getattr(e, "response", None), "status_code", None)
                errors.append(f"{urlsplit(url).hostname}: {f'HTTP {status}' if status else type(e).__name__}")
    row = db.get(AppSetting, "news")
    old = (row.value or {}) if row else {}
    if not items and errors:
        items = old.get("items", [])  # all feeds failed: keep showing what we had
    seen, newest = set(), []
    for i in sorted(items, key=lambda i: i["published"] or "", reverse=True):
        if i["url"] not in seen:
            seen.add(i["url"])
            newest.append(i)
    db.merge(AppSetting(key="news", value={"items": newest[:KEEP], "errors": errors,
                                          "updated_at": utcnow().isoformat() if not errors or len(errors) < len(urls)
                                          else old.get("updated_at")}))
    db.commit()
    return len(newest[:KEEP])


def stored(db: Session) -> dict:
    row = db.get(AppSetting, "news")
    v = (row.value or {}) if row else {}
    return {"enabled": bool(feeds()), "items": v.get("items", []), "errors": v.get("errors", []),
            "updated_at": v.get("updated_at")}
