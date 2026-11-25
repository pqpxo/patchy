"""v1.22: visitors a proxy or CDN rate-limits are sent to a page of the operator's choosing."""
from app import main
from app.config import Settings, settings


def test_blocked_url_is_in_the_page_escaped(client, monkeypatch, tmp_path):
    (tmp_path / "index.html").write_text("<!doctype html><html><head><title>Patchy</title></head></html>")
    monkeypatch.setattr(main, "STATIC", tmp_path)
    assert "blocked-url" not in client.get("/hosts").text  # off unless set
    monkeypatch.setattr(settings, "blocked_url", 'https://error.example/?a=1&b="x"')
    page = client.get("/hosts").text
    assert '<head><meta name="blocked-url" content="https://error.example/?a=1&amp;b=&quot;x&quot;">' in page


def test_only_web_addresses_are_accepted(monkeypatch):
    monkeypatch.setenv("BLOCKED_URL", "javascript:alert(1)")
    assert Settings().blocked_url == ""
    monkeypatch.setenv("BLOCKED_URL", " https://error.example/ ")
    assert Settings().blocked_url == "https://error.example/"
