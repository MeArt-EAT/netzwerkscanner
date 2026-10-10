"""Sicherheitsregeln des Webservers: Host, Origin, Content-Type, Kopfzeilen, WebSocket, Start auf 127.0.0.1."""

from __future__ import annotations

import inspect
import socket
import threading

import pytest
import uvicorn
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketDenialResponse
from starlette.websockets import WebSocketDisconnect

from netscan import config
from netscan.web import server
from tests.test_api_support import (  # noqa: F401  (Fixtures env und client)
    BASE,
    PORT,
    add_devices,
    client,
    env,
    make_env,
    sample_device,
)

EVIL = "http://evil.example"
WS_URL = "ws://127.0.0.1:8765/ws"  # der TestClient nimmt für WebSockets sonst „testserver“ als Host
EXPECTED_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self' ws://127.0.0.1:8765 ws://localhost:8765; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


# --- Host (DNS-Rebinding) --------------------------------------------------------------------


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8765", "127.0.0.1.evil.example", "192.168.178.20:8765", "[::1]:8765"])
def test_fremder_host_ergibt_400(client, host):
    for path in ("/api/status", "/", "/api/devices"):
        r = client.get(path, headers={"host": host})
        assert r.status_code == 400, (host, path)
    assert client.post("/api/scan/cancel", headers={"host": host}).status_code == 400


@pytest.mark.parametrize("host", ["127.0.0.1:8765", "127.0.0.1", "localhost:8765", "localhost"])
def test_erlaubte_hosts(client, host):
    assert client.get("/api/job", headers={"host": host}).status_code == 200


def test_testserver_host_ist_nicht_erlaubt(env):
    """Ohne base_url nimmt der TestClient „testserver“ – der Server lehnt das ab."""
    with TestClient(env.app) as plain:
        assert plain.get("/api/job").status_code == 400


# --- Origin ----------------------------------------------------------------------------------


@pytest.mark.parametrize("origin", [EVIL, "null", "http://127.0.0.1:9999", "https://127.0.0.1:8765", "http://127.0.0.1.evil.example:8765", "http://localhost"])
@pytest.mark.parametrize(
    "method, path, body",
    [
        ("post", "/api/scan", {"adapter": "Ethernet"}),
        ("post", "/api/scan/cancel", None),
        ("put", "/api/settings", {"rate_pps": 100}),
        ("patch", "/api/devices/aa:bb:cc:dd:ee:01", {"note": "x"}),
        ("delete", "/api/devices/aa:bb:cc:dd:ee:01", None),
        ("post", "/api/oui/update", None),
    ],
)
def test_fremder_origin_ergibt_403(client, env, origin, method, path, body):
    kwargs = {"headers": {"origin": origin}}
    if body is not None:
        kwargs["json"] = body
    r = getattr(client, method)(path, **kwargs)
    assert r.status_code == 403
    assert env.scan_calls == [] and env.guard.checked == []
    assert env.svc.jobs.status().state == "idle"
    assert env.svc.settings.load().rate_pps == 200


@pytest.mark.parametrize("origin", [BASE, "http://localhost:8765", "HTTP://LOCALHOST:8765"])
def test_eigener_origin_ist_erlaubt(client, env, origin):
    r = client.post("/api/scan", json={"adapter": "Ethernet"}, headers={"origin": origin})
    assert r.status_code == 202
    env.wait_job()
    assert client.put("/api/settings", json={"rate_pps": 100}, headers={"origin": origin}).status_code == 200


def test_ohne_origin_ist_erlaubt(client, env):
    """curl und Skripte senden keinen Origin."""
    assert client.post("/api/scan/cancel").status_code == 200


def test_lesende_anfragen_pruefen_den_origin_nicht(client):
    assert client.get("/api/job", headers={"origin": EVIL}).status_code == 200


def test_keine_cors_freigabe(client):
    r = client.get("/api/job", headers={"origin": EVIL})
    assert not any(k.lower().startswith("access-control-") for k in r.headers)
    r = client.options("/api/scan", headers={"origin": EVIL, "access-control-request-method": "POST"})
    assert r.status_code == 405
    assert not any(k.lower().startswith("access-control-") for k in r.headers)


# --- Content-Type ----------------------------------------------------------------------------


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "application/jsonx", "text/json"])
def test_falscher_content_type_ergibt_415(client, env, content_type):
    r = client.post("/api/scan", content=b'{"adapter": "Ethernet"}', headers={"content-type": content_type})
    assert r.status_code == 415
    assert env.guard.checked == [] and env.scan_calls == []
    r = client.put("/api/settings", content=b'{"rate_pps": 100}', headers={"content-type": content_type})
    assert r.status_code == 415
    assert env.svc.settings.load().rate_pps == 200


def test_body_ohne_content_type_ergibt_415(client, env):
    r = client.post("/api/scan", content=b'{"adapter": "Ethernet"}', headers={"content-type": ""})
    assert r.status_code == 415
    assert env.scan_calls == []


def test_chunked_body_ohne_json_ergibt_415(client, env):
    def chunks():
        yield b'{"adapter": '
        yield b'"Ethernet"}'

    r = client.post("/api/scan", content=chunks(), headers={"content-type": "text/plain"})
    assert r.status_code == 415
    assert env.scan_calls == []


@pytest.mark.parametrize("content_type", ["application/json", "application/json; charset=utf-8", "Application/JSON"])
def test_json_content_type_wird_akzeptiert(client, env, content_type):
    r = client.post("/api/scan", content=b'{"adapter": "Ethernet"}', headers={"content-type": content_type})
    assert r.status_code == 202
    env.wait_job()


def test_ohne_body_braucht_keinen_content_type(client):
    assert client.post("/api/scan/cancel").status_code == 200
    assert client.post("/api/scan/cancel", headers={"content-type": "text/plain"}).status_code == 200


def test_lesende_anfrage_mit_anderem_content_type(client):
    assert client.get("/api/job", headers={"content-type": "text/plain"}).status_code == 200


# --- Kopfzeilen ------------------------------------------------------------------------------


def test_schutz_kopfzeilen_auf_allen_antworten(client, env):
    add_devices(env.svc, sample_device())
    antworten = [
        client.get("/"),
        client.get("/api/status"),
        client.get("/api/export/html"),
        client.get("/api/devices/aa:bb:cc:00:00:77"),  # 404
        client.post("/api/scan", json={}),  # 422
        client.post("/api/scan/cancel", headers={"origin": EVIL}),  # 403
        client.post("/api/scan", content=b"x", headers={"content-type": "text/plain"}),  # 415
        client.get("/static/gibt-es-nicht.js"),
    ]
    for r in antworten:
        assert r.headers["x-content-type-options"] == "nosniff", r.url
        assert r.headers["x-frame-options"] == "DENY", r.url
        assert r.headers["referrer-policy"] == "no-referrer", r.url
        assert r.headers["content-security-policy"] == EXPECTED_CSP, r.url


def test_csp_hat_keine_inline_skripte_und_keine_fremden_adressen(client):
    csp = client.get("/api/status").headers["content-security-policy"]
    script_src = next(part for part in csp.split(";") if part.strip().startswith("script-src"))
    assert script_src.strip() == "script-src 'self'"
    assert "http://" not in csp and "https://" not in csp and "*" not in csp


def test_csp_folgt_dem_port(services, monkeypatch):
    env = make_env(services, monkeypatch, port=9000)
    with TestClient(env.app, base_url="http://127.0.0.1:9000") as c:
        csp = c.get("/api/status").headers["content-security-policy"]
        assert "ws://127.0.0.1:9000 ws://localhost:9000" in csp
        assert c.post("/api/scan/cancel", headers={"origin": "http://127.0.0.1:9000"}).status_code == 200
        assert c.post("/api/scan/cancel", headers={"origin": BASE}).status_code == 403


def test_automatische_dokumentation_ist_aus(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


# --- Oberfläche und statische Dateien --------------------------------------------------------


def test_startseite_und_statische_dateien(services, monkeypatch, tmp_path):
    static = tmp_path / "static"
    (static / "vendor").mkdir(parents=True)
    (static / "index.html").write_text("<!doctype html><title>Test</title><script src=\"/static/app.js\"></script>", encoding="utf-8")
    (static / "app.js").write_text("console.log(1);", encoding="utf-8")
    (static / "style.css").write_text("body{}", encoding="utf-8")
    monkeypatch.setattr(config, "STATIC_DIR", static)
    env = make_env(services, monkeypatch)
    with TestClient(env.app, base_url=BASE) as c:
        r = c.get("/")
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
        assert "<title>Test</title>" in r.text
        js = c.get("/static/app.js")
        assert js.status_code == 200 and js.headers["content-type"].split(";")[0] == "text/javascript"
        assert c.get("/static/style.css").headers["content-type"].split(";")[0] == "text/css"
        assert c.get("/static/../server.py").status_code == 404
        assert c.get("/static/%2e%2e/%2e%2e/netscan/web/server.py").status_code == 404


def test_ersatzseite_wenn_index_fehlt(services, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "STATIC_DIR", tmp_path / "gibt-es-nicht")
    env = make_env(services, monkeypatch)
    with TestClient(env.app, base_url=BASE) as c:
        r = c.get("/")
        assert r.status_code == 200
        assert "Netzwerkscanner" in r.text and "<script" not in r.text.lower()
        assert c.get("/static/app.js").status_code == 404


# --- WebSocket -------------------------------------------------------------------------------


def _watchdog(ws, seconds: float = 10.0) -> threading.Timer:
    """Beendet die Verbindung, falls ein Test hängt (receive_* blockiert sonst ewig)."""
    timer = threading.Timer(seconds, ws.close)
    timer.daemon = True
    timer.start()
    return timer


def test_websocket_hello_und_ereignisse(client, env):
    with client.websocket_connect(WS_URL, headers={"origin": BASE}) as ws:
        timer = _watchdog(ws)
        try:
            hello = ws.receive_json()
            assert hello["type"] == "hello"
            status = hello["data"]["status"]
            assert status["version"] and status["platform"] == "fake"
            assert set(status) >= {"version", "platform", "admin", "scapy", "oui", "job", "guard"}

            env.svc.bus.publish("job.log", {"job_id": "x1", "level": "info", "message": "Grüße aus dem Scan"}, job_id="x1")
            event = ws.receive_json()
            assert event["type"] == "job.log"
            assert event["data"]["message"] == "Grüße aus dem Scan"
            assert event["job_id"] == "x1" and event["seq"] >= 1 and event["ts"]

            env.svc.bus.publish("devices.changed", {})
            assert ws.receive_json()["type"] == "devices.changed"
        finally:
            timer.cancel()


def test_websocket_meldet_auftragsereignisse(client, env):
    with client.websocket_connect(WS_URL) as ws:  # ohne Origin erlaubt
        timer = _watchdog(ws)
        try:
            assert ws.receive_json()["type"] == "hello"
            assert client.post("/api/scan", json={"adapter": "Ethernet"}).status_code == 202
            seen: list[str] = []
            while "job.finished" not in seen:
                seen.append(ws.receive_json()["type"])
            assert "guard.result" in seen and "job.started" in seen
            assert seen.index("job.started") < seen.index("job.finished")
        finally:
            timer.cancel()


def test_websocket_origin_localhost_erlaubt(client):
    with client.websocket_connect(WS_URL, headers={"origin": "http://localhost:8765"}) as ws:
        timer = _watchdog(ws)
        try:
            assert ws.receive_json()["type"] == "hello"
        finally:
            timer.cancel()


@pytest.mark.parametrize("origin", [EVIL, "null", "http://127.0.0.1:9999", "http://127.0.0.1"])
def test_websocket_fremder_origin_wird_abgewiesen(client, env, origin):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(WS_URL, headers={"origin": origin}) as ws:
            ws.receive_json()
    assert exc.value.code == 1008
    # kein Abonnent bleibt zurück
    assert env.svc.bus._subs == []


def test_websocket_meldet_sich_beim_trennen_ab(client, env):
    with client.websocket_connect(WS_URL) as ws:
        timer = _watchdog(ws)
        try:
            ws.receive_json()
            assert len(env.svc.bus._subs) == 1
        finally:
            timer.cancel()
    # Das Aufräumen läuft im Server-Thread; kurz warten
    for _ in range(100):
        if not env.svc.bus._subs:
            break
        threading.Event().wait(0.05)
    assert env.svc.bus._subs == []


def test_websocket_fremder_host_wird_abgewiesen(client, env):
    with pytest.raises(WebSocketDenialResponse) as exc:
        with client.websocket_connect(WS_URL, headers={"host": "evil.example"}) as ws:
            ws.receive_json()
    assert exc.value.status_code == 400
    assert env.svc.bus._subs == []


def test_lifespan_haengt_schleife_an_und_ab(env):
    with TestClient(env.app, base_url=BASE) as c:
        assert env.svc.bus._loop is not None
        assert c.get("/api/job").status_code == 200
    assert env.svc.bus._loop is None
    assert env.svc.db is not None and env.svc.db.query("SELECT 1")  # übergebene Dienste bleiben offen


def test_app_baut_dienste_selbst_und_schliesst_sie(data_dir, fake_platform, monkeypatch):
    from netscan.core.services import build_services
    from tests.fakes import FakeOui

    built = []

    def fake_build():
        svc = build_services(data_dir=data_dir, platform=fake_platform, oui=FakeOui())
        built.append(svc)
        return svc

    monkeypatch.setattr(server, "build_services", fake_build)
    app = server.create_app(None)
    with TestClient(app, base_url=BASE) as c:
        assert len(built) == 1
        assert c.get("/api/job").status_code == 200
        assert built[0].bus._loop is not None
    assert built[0].bus._loop is None
    with pytest.raises(Exception):  # Datenbank wurde geschlossen
        built[0].db.query("SELECT 1")


def test_ohne_dienste_vor_dem_start_503(monkeypatch):
    app = server.create_app(None)
    c = TestClient(app, base_url=BASE)  # ohne with: Lifespan lief nicht
    assert c.get("/api/job").status_code == 503


# --- Start auf 127.0.0.1 ---------------------------------------------------------------------


class FakeServer:
    """Ersatz für uvicorn.Server: startet nichts, merkt sich nur die Konfiguration."""

    instances: list[FakeServer] = []

    def __init__(self, config: uvicorn.Config) -> None:
        self.config = config
        self.started = True
        self.ran = False
        FakeServer.instances.append(self)

    def run(self) -> None:
        self.ran = True


@pytest.fixture
def fake_uvicorn(monkeypatch):
    FakeServer.instances = []
    real_config = uvicorn.Config
    # log_config=None: die Prüfung soll das Logging des Testlaufs nicht umbauen
    monkeypatch.setattr(uvicorn, "Config", lambda *a, **kw: real_config(*a, log_config=None, **kw))
    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    return FakeServer


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_bind_host_ist_loopback():
    assert server.BIND_HOST == "127.0.0.1"


def test_run_hat_keine_option_fuer_die_adresse():
    assert list(inspect.signature(server.run).parameters) == ["port", "open_browser", "services"]
    assert list(inspect.signature(server.create_app).parameters) == ["services", "port"]


def test_run_uebergibt_bind_host_an_uvicorn(fake_uvicorn, env):
    port = _free_port()
    server.run(port=port, open_browser=False, services=env.svc)
    (srv,) = fake_uvicorn.instances
    assert srv.ran is True
    assert srv.config.host == "127.0.0.1"
    assert srv.config.port == port
    assert srv.config.log_level == "info"


def test_run_standardport_und_host(fake_uvicorn, env, monkeypatch):
    monkeypatch.setattr(server, "_port_is_free", lambda port: True)
    server.run(services=env.svc)
    (srv,) = fake_uvicorn.instances
    assert config.DEFAULT_PORT == PORT == 8765
    assert (srv.config.host, srv.config.port) == ("127.0.0.1", 8765)


def test_run_oeffnet_browser_nach_dem_start(fake_uvicorn, env, monkeypatch):
    import webbrowser

    opened: list[str] = []
    monkeypatch.setattr(webbrowser, "open", lambda url, *a, **k: opened.append(url) or True)
    port = _free_port()
    server.run(port=port, open_browser=True, services=env.svc)
    assert opened == [f"http://127.0.0.1:{port}/"]


def test_run_ohne_browser_oeffnet_nichts(fake_uvicorn, env, monkeypatch):
    import webbrowser

    opened: list[str] = []
    monkeypatch.setattr(webbrowser, "open", lambda url, *a, **k: opened.append(url) or True)
    server.run(port=_free_port(), open_browser=False, services=env.svc)
    assert opened == []


def test_run_browser_nur_wenn_server_gestartet_ist(fake_uvicorn, env, monkeypatch):
    import webbrowser

    opened: list[str] = []
    monkeypatch.setattr(webbrowser, "open", lambda url, *a, **k: opened.append(url) or True)

    class NieGestartet(FakeServer):
        def __init__(self, config):
            super().__init__(config)
            self.started = False

    monkeypatch.setattr(uvicorn, "Server", NieGestartet)
    server.run(port=_free_port(), open_browser=True, services=env.svc)
    assert opened == []


def test_run_belegter_port_ergibt_exit_code_2(fake_uvicorn, env, caplog):
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        port = blocker.getsockname()[1]
        with caplog.at_level("ERROR"):
            with pytest.raises(SystemExit) as exc:
                server.run(port=port, open_browser=True, services=env.svc)
        assert exc.value.code == 2
        assert f"Port {port} ist belegt – läuft der Scanner schon?" in caplog.text
        assert fake_uvicorn.instances == []  # uvicorn wurde gar nicht erst gebaut
    finally:
        blocker.close()


def test_port_pruefung_gibt_den_port_nach_dem_test_wieder_frei(fake_uvicorn, env):
    port = _free_port()
    server.run(port=port, services=env.svc)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", port))  # Prüfsocket ist geschlossen
