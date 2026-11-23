"""v1.9: security news on the Overview, from RSS/Atom feeds fetched by the worker."""
import httpx
import pytest

from app import news
from app.config import settings

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>Sec &amp; News</title>
<item><title>Old &lt;b&gt;post&lt;/b&gt;</title><link>https://n.example/old</link><pubDate>Mon, 23 Nov 2026 09:00:00 -0500</pubDate></item>
<item><title>Plain http</title><link>http://n.example/http</link><pubDate>Mon, 23 Nov 2026 20:00:00 GMT</pubDate></item>
<item><title>Script</title><link>javascript:alert(1)</link></item>
<item><title>Undated</title><link>https://n.example/undated</link></item>
</channel></rss>"""
ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>Atom Feed</title>
<entry><title>Newest</title><link rel="alternate" href="https://a.example/new"/><updated>2026-11-23T15:00:00Z</updated></entry>
<entry><title>Dup</title><link href="https://n.example/old"/><published>2026-11-20T10:00:00Z</published></entry>
</feed>"""


def _client(routes):
    def handler(req):
        body = routes[str(req.url)]
        return body if isinstance(body, httpx.Response) else httpx.Response(200, content=body)
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


def test_rss_and_atom_are_merged_newest_first(monkeypatch, auth_client, db):
    monkeypatch.setattr(settings, "news_feeds", "https://n.example/rss, https://a.example/atom, http://insecure/x")
    assert news.refresh(db, _client({"https://n.example/rss": RSS, "https://a.example/atom": ATOM})) == 3
    out = auth_client.get("/api/news").json()
    assert out["enabled"] and out["errors"] == [] and out["updated_at"]
    assert [(i["title"], i["source"]) for i in out["items"]] == [
        ("Newest", "Atom Feed"), ("Old post", "Sec & News"), ("Undated", "Sec & News")]  # http/js links dropped
    assert out["items"][1]["published"] == "2026-11-23T14:00:00+00:00"  # stored in UTC, so it sorts correctly


def test_a_failing_feed_keeps_the_rest_and_old_posts(monkeypatch, db):
    monkeypatch.setattr(settings, "news_feeds", "https://n.example/rss,https://down.example/rss")
    routes = {"https://n.example/rss": RSS, "https://down.example/rss": httpx.Response(503)}
    assert news.refresh(db, _client(routes)) == 2
    assert news.stored(db)["errors"] == ["down.example: HTTP 503"]
    routes["https://n.example/rss"] = b"<rss><channel><item>"  # broken XML: everything failed
    assert news.refresh(db, _client(routes)) == 2  # the posts we had are kept
    assert news.stored(db)["errors"] == ["n.example: ParseError", "down.example: HTTP 503"]


def test_hostile_feeds_are_refused(monkeypatch):
    bomb = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><rss><channel><title>&a;</title></channel></rss>'
    with pytest.raises(ValueError):
        news.parse(bomb, "https://x.example")
    redirect = {"https://r.example/f": httpx.Response(302, headers={"Location": "http://r.example/f"}),
                "http://r.example/f": RSS}
    with pytest.raises(ValueError), _client(redirect) as c:
        news._get(c, "https://r.example/f")
    monkeypatch.setattr(news, "MAX_BYTES", 100)
    with pytest.raises(ValueError), _client({"https://big.example/f": RSS}) as c:
        news._get(c, "https://big.example/f")


def test_off_when_no_feeds(monkeypatch, auth_client, db):
    monkeypatch.setattr(settings, "news_feeds", "")
    assert news.refresh(db) == 0 and auth_client.get("/api/news").json()["enabled"] is False
