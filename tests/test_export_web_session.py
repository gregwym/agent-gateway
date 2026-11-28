import json
import stat
import sys

import pytest

from agent_gateway import export_web_session


@pytest.mark.parametrize(
    "site, login, expected",
    [
        ("amazon-orders", None, None),
        ("amazon-orders", {"expires": 1}, None),
        ("amazon-orders", {"domain": ".amazon.co.uk"}, None),
        ("amazon-orders", {"path": "/unrelated"}, None),
        ("amazon-orders", {"value": '"synthetic;invalid"'}, None),
        ("amazon-orders", {"value": '""'}, None),
        ("amazon-orders", {}, "synthetic-login"),
        ("amazon-orders", {"value": '"synthetic-login"'}, '"synthetic-login"'),
        ("amazon-us", {"value": '"synthetic-login"'}, None),
    ],
)
def test_export_validates_the_session_before_writing(tmp_path, monkeypatch, capsys, site, login, expected):
    visitor = {"name": "session-id", "value": "synthetic-guest", "domain": ".amazon.com", "path": "/", "expires": -1}
    cookies = [visitor]
    if login is not None:
        cookies.append({**visitor, "name": "x-main", "value": "synthetic-login", **login})
    output = tmp_path / "session.json"
    monkeypatch.setattr(sys, "argv", ["agw-export-session", site, str(output)])
    monkeypatch.setattr(export_web_session, "find_chrome", lambda _: "synthetic-chrome")
    monkeypatch.setattr(export_web_session, "sign_in", lambda *args: 0)
    monkeypatch.setattr(export_web_session, "saved_cookies", lambda *args: cookies)

    if site == "amazon-orders" and expected is None:
        with pytest.raises(SystemExit) as error:
            export_web_session.main()
        assert error.value.code == 1
        assert "No valid Amazon Orders sign-in" in capsys.readouterr().err
        assert not output.exists()
        return

    export_web_session.main()
    exported = {cookie["name"]: cookie["value"] for cookie in json.loads(output.read_text())}
    assert exported.get("x-main") == expected
    assert exported["session-id"] == visitor["value"]
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    messages = capsys.readouterr()
    assert all(value.strip('"') not in messages.out + messages.err for value in exported.values())
