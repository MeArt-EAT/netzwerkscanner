"""Herstellerliste: Laden, Suche, zufällige MAC, Update aus der IEEE-CSV (nur mit Fake-Fetch, nie Internet)."""

from __future__ import annotations

import gzip
import io
import os
import time
import urllib.error
from pathlib import Path

import pytest

from netscan.net import oui
from netscan.net.oui import OUI_URL, OuiDb, is_random_mac, update_from_ieee

CSV_HEAD = "Registry,Assignment,Organization Name,Organization Address\n"


def write_tsv(path: Path, text: str) -> None:
    with gzip.open(path, "wt", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def read_tsv(path: Path) -> list[str]:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return handle.read().splitlines()


def small_csv() -> bytes:
    rows = [
        'MA-L,3CA62F,"AVM Audiovisuelle Marketing, Computersysteme GmbH","Alt-Moabit 95 Berlin DE 10559"',
        'MA-L,001132,Synology Incorporated,"No.1, Yuandong Rd. New Taipei City TW"',
        'MA-L,28EE52,"TP-LINK TECHNOLOGIES CO.,LTD.",',
        'MA-L,B827EB,"Raspberry Pi ""Foundation""","Mitchell Wood, Caldecote"',
        "MA-L,00000C,Cisco Systems\tInc,San Jose",
    ]
    return (CSV_HEAD + "\n".join(rows) + "\n").encode("utf-8")


def fake_fetch(payload: bytes, seen: list[str] | None = None):  # type: ignore[no-untyped-def]
    def fetch(url: str) -> bytes:
        if seen is not None:
            seen.append(url)
        return payload

    return fetch


# --- is_random_mac ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "mac",
    ["da:a1:19:00:00:01", "02:00:00:00:00:00", "FA-AA-BB-CC-DD-EE", "d6:11:22:33:44:55", "0A1B2C3D4E5F", "06:00:00:00:00:01"],
)
def test_locally_administered_macs_are_random(mac: str) -> None:
    assert is_random_mac(mac) is True


@pytest.mark.parametrize(
    "mac",
    ["00:11:32:aa:bb:cc", "3c:a6:2f:00:00:01", "a4:c3:61:00:00:21", "B8:27:EB:00:00:01", "01:00:5e:00:00:01"],
)
def test_globally_assigned_macs_are_not_random(mac: str) -> None:
    # 01:00:5e ist Multicast (Bit 0), aber nicht „locally administered“ (Bit 1)
    assert is_random_mac(mac) is False


def test_broadcast_has_the_locally_administered_bit() -> None:
    assert is_random_mac("ff:ff:ff:ff:ff:ff") is True


@pytest.mark.parametrize("bad", ["", "xyz", "00:11:32", "gg:11:22:33:44:55", None, 42])
def test_invalid_mac_is_not_random_and_does_not_raise(bad: object) -> None:
    assert is_random_mac(bad) is False  # type: ignore[arg-type]


# --- mitgelieferte Liste -----------------------------------------------------------------


def test_bundled_list_is_loaded() -> None:
    db = OuiDb.load(None)
    assert db.entries > 40000
    assert db.source.startswith("mitgeliefert (Stand ")
    assert db.source.endswith(")")


def test_bundled_lookups() -> None:
    db = OuiDb.load(None)
    assert db.lookup("00:11:32:aa:bb:cc") == "Synology Incorporated"
    assert "AVM" in (db.lookup("3c:a6:2f:12:34:56") or "")
    assert db.lookup("3C-A6-2F-12-34-56") == db.lookup("3ca62f123456")
    assert db.lookup("0011.32aa.bbcc") == "Synology Incorporated"


def test_first_entry_of_bundled_list() -> None:
    assert OuiDb.load(None).lookup("00:00:00:00:00:01") == "XEROX CORPORATION"


def test_unlisted_prefix_gives_none(tmp_path: Path) -> None:
    write_tsv(tmp_path / "oui.tsv.gz", "00AA11\tEchte GmbH\n")
    assert OuiDb.load(tmp_path).lookup("10:20:30:00:00:01") is None


def test_random_mac_has_no_manufacturer() -> None:
    db = OuiDb.load(None)
    # 02:11:32 hat dieselben Bytes 2 und 3 wie ein Synology-Gerät, ist aber eine private Adresse
    assert db.lookup("02:11:32:aa:bb:cc") is None
    assert db.lookup("da:a1:19:12:34:56") is None


def test_invalid_mac_lookup_gives_none() -> None:
    db = OuiDb.load(None)
    for bad in ("", "kein-mac", "00:11:32", None, 7):
        assert db.lookup(bad) is None  # type: ignore[arg-type]


def test_load_without_argument_uses_only_the_bundled_list() -> None:
    assert OuiDb.load().source.startswith("mitgeliefert")


def test_data_dir_without_updated_list_uses_bundled(tmp_path: Path) -> None:
    db = OuiDb.load(tmp_path)
    assert db.source.startswith("mitgeliefert")
    assert db.entries > 40000


def test_bundled_header_without_date(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    bundled = tmp_path / "b.tsv.gz"
    write_tsv(bundled, "# ohne Datum\n001132\tSynology Incorporated\n")
    monkeypatch.setattr(oui, "BUNDLED_OUI", bundled)
    db = OuiDb.load(None)
    assert db.source == "mitgeliefert"
    assert db.entries == 1


def test_missing_bundled_list_gives_empty_database(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(oui, "BUNDLED_OUI", tmp_path / "gibt-es-nicht.tsv.gz")
    db = OuiDb.load(None)
    assert db.entries == 0
    assert db.lookup("00:11:32:aa:bb:cc") is None
    assert db.source


# --- aktualisierte Liste hat Vorrang ------------------------------------------------------


def set_file_date(path: Path, year: int, month: int, day: int) -> None:
    stamp = time.mktime((year, month, day, 12, 0, 0, 0, 0, -1))
    os.utime(path, (stamp, stamp))


def test_updated_list_in_data_dir_takes_precedence(tmp_path: Path) -> None:
    user = tmp_path / "oui.tsv.gz"
    write_tsv(user, "# Testliste - Stand 2020-01-01\n00AA11\tNeuer Hersteller GmbH\n001132\tUmbenannt AG\n")
    set_file_date(user, 2026, 11, 2)
    db = OuiDb.load(tmp_path)
    assert db.entries == 2
    assert db.source == "aktualisiert 2026-11-02"
    assert db.lookup("00:aa:11:00:00:01") == "Neuer Hersteller GmbH"
    assert db.lookup("00:11:32:aa:bb:cc") == "Umbenannt AG"
    assert db.lookup("3c:a6:2f:12:34:56") is None  # steht nur in der mitgelieferten Liste


def test_comments_blank_and_broken_lines_are_skipped(tmp_path: Path) -> None:
    write_tsv(
        tmp_path / "oui.tsv.gz",
        "# Kommentar\n\n   \n#00AA11\tAuskommentiert\n00bb22\tKlein geschrieben\nXYZ\tKurz\n00CC33\n00DD44\t \nZZZZZZ\tKein Hex\n  # eingerückter Kommentar\n00EE55\tOK\n",
    )
    db = OuiDb.load(tmp_path)
    assert db.entries == 2
    assert db.lookup("00:bb:22:00:00:01") == "Klein geschrieben"
    assert db.lookup("00:ee:55:00:00:01") == "OK"
    assert db.lookup("00:aa:11:00:00:01") is None


def test_random_mac_is_none_even_if_prefix_is_listed(tmp_path: Path) -> None:
    write_tsv(tmp_path / "oui.tsv.gz", "DAA119\tZufall AG\n00AA11\tEchte GmbH\n")
    db = OuiDb.load(tmp_path)
    assert db.lookup("da:a1:19:00:00:01") is None
    assert db.lookup("00:aa:11:00:00:01") == "Echte GmbH"


def test_corrupt_updated_list_falls_back_to_bundled(tmp_path: Path) -> None:
    (tmp_path / "oui.tsv.gz").write_bytes(b"das ist kein gzip")
    db = OuiDb.load(tmp_path)
    assert db.source.startswith("mitgeliefert")
    assert db.lookup("00:11:32:aa:bb:cc") == "Synology Incorporated"


def test_empty_updated_list_falls_back_to_bundled(tmp_path: Path) -> None:
    write_tsv(tmp_path / "oui.tsv.gz", "# nur Kopf\n")
    assert OuiDb.load(tmp_path).source.startswith("mitgeliefert")


# --- update_from_ieee ------------------------------------------------------------------


def test_update_with_fake_fetch_writes_list_and_takes_precedence(tmp_path: Path) -> None:
    seen: list[str] = []
    count = update_from_ieee(tmp_path, fake_fetch(small_csv(), seen), min_entries=1)
    assert count == 5
    assert seen == [OUI_URL]
    target = tmp_path / "oui.tsv.gz"
    assert target.is_file()

    lines = read_tsv(target)
    assert lines[0].startswith("# IEEE MA-L")
    assert "Stand " + time.strftime("%Y-%m-%d") in lines[0]
    assert lines[1:] == sorted(lines[1:])
    assert len(lines) == 6

    db = OuiDb.load(tmp_path)
    assert db.entries == 5
    assert db.source == "aktualisiert " + time.strftime("%Y-%m-%d")
    assert db.lookup("3c:a6:2f:00:00:01") == "AVM Audiovisuelle Marketing, Computersysteme GmbH"
    assert db.lookup("28:ee:52:00:00:01") == "TP-LINK TECHNOLOGIES CO.,LTD."
    assert db.lookup("b8:27:eb:00:00:01") == 'Raspberry Pi "Foundation"'
    assert db.lookup("00:00:0c:00:00:01") == "Cisco Systems Inc"  # Tabulator im Namen wird zu Leerzeichen
    assert db.lookup("00:11:32:aa:bb:cc") == "Synology Incorporated"


def test_update_keeps_no_raw_file_and_no_temp_file(tmp_path: Path) -> None:
    update_from_ieee(tmp_path, fake_fetch(small_csv()), min_entries=1)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["oui.tsv.gz"]


def test_update_replaces_existing_list(tmp_path: Path) -> None:
    write_tsv(tmp_path / "oui.tsv.gz", "# alt\n00AA11\tAlter Hersteller\n")
    update_from_ieee(tmp_path, fake_fetch(small_csv()), min_entries=1)
    db = OuiDb.load(tmp_path)
    assert db.lookup("00:aa:11:00:00:01") is None
    assert db.entries == 5


def test_update_creates_missing_data_dir(tmp_path: Path) -> None:
    folder = tmp_path / "neu" / "data"
    assert update_from_ieee(folder, fake_fetch(small_csv()), min_entries=1) == 5
    assert (folder / "oui.tsv.gz").is_file()


def test_too_small_list_is_rejected_and_old_list_stays(tmp_path: Path) -> None:
    target = tmp_path / "oui.tsv.gz"
    write_tsv(target, "# alt\n00AA11\tAlter Hersteller\n")
    before = target.read_bytes()
    with pytest.raises(ValueError, match="Einträge"):
        update_from_ieee(tmp_path, fake_fetch(small_csv()))  # Standard: min_entries=10000
    assert target.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["oui.tsv.gz"]
    assert OuiDb.load(tmp_path).lookup("00:aa:11:00:00:01") == "Alter Hersteller"


def test_min_entries_is_a_lower_bound(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        update_from_ieee(tmp_path, fake_fetch(small_csv()), min_entries=6)
    assert not (tmp_path / "oui.tsv.gz").exists()
    assert update_from_ieee(tmp_path, fake_fetch(small_csv()), min_entries=5) == 5


def test_large_list_passes_default_threshold(tmp_path: Path) -> None:
    rows = "".join(f"MA-L,{i:06X},Hersteller {i},Adresse\n" for i in range(10000))
    assert update_from_ieee(tmp_path, fake_fetch((CSV_HEAD + rows).encode())) == 10000


def test_html_error_page_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "oui.tsv.gz"
    write_tsv(target, "00AA11\tAlt\n")
    page = b"<html><body>403 Forbidden</body></html>"
    with pytest.raises(ValueError, match="Format"):
        update_from_ieee(tmp_path, fake_fetch(page), min_entries=1)
    assert OuiDb.load(tmp_path).lookup("00:aa:11:00:00:01") == "Alt"


def test_rows_without_valid_assignment_or_name_are_ignored(tmp_path: Path) -> None:
    csv_text = CSV_HEAD + "MA-L,00AA11,Gut,x\nMA-L,XYZ,Kein Hex,x\nMA-L,00AA1,Zu kurz,x\nMA-L,00AA22,,x\nMA-L,00AA33\n"
    assert update_from_ieee(tmp_path, fake_fetch(csv_text.encode()), min_entries=1) == 1


def test_csv_with_bom_and_crlf(tmp_path: Path) -> None:
    payload = ("﻿" + CSV_HEAD + "MA-L,00AA11,Gut GmbH,x\r\nMA-L,00AA22,\"Zwei, Komma\",x\r\n").encode("utf-8")
    assert update_from_ieee(tmp_path, fake_fetch(payload), min_entries=1) == 2
    assert OuiDb.load(tmp_path).lookup("00:aa:22:00:00:01") == "Zwei, Komma"


def test_failed_write_keeps_old_list_and_leaves_no_temp_file(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "oui.tsv.gz"
    write_tsv(target, "00AA11\tAlt\n")
    before = target.read_bytes()

    def broken_replace(src, dst):  # type: ignore[no-untyped-def]
        raise OSError("Platte voll")

    monkeypatch.setattr(oui.os, "replace", broken_replace)
    with pytest.raises(OSError, match="Platte voll"):
        update_from_ieee(tmp_path, fake_fetch(small_csv()), min_entries=1)
    assert target.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["oui.tsv.gz"]


def test_fetch_error_propagates_and_changes_nothing(tmp_path: Path) -> None:
    def fetch(url: str) -> bytes:
        raise OSError("keine Verbindung")

    with pytest.raises(OSError, match="keine Verbindung"):
        update_from_ieee(tmp_path, fetch, min_entries=1)
    assert list(tmp_path.iterdir()) == []


# --- Standard-Fetch (urlopen ist ersetzt, es geht nichts ins Netz) --------------------------


class FakeResponse(io.BytesIO):
    def __enter__(self):  # type: ignore[no-untyped-def]
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def test_default_fetch_uses_timeout_and_user_agent(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    calls: list[tuple[object, object]] = []

    def fake_urlopen(request, timeout=None):  # type: ignore[no-untyped-def]
        calls.append((request, timeout))
        return FakeResponse(small_csv())

    monkeypatch.setattr(oui.urllib.request, "urlopen", fake_urlopen)
    assert update_from_ieee(tmp_path, min_entries=1) == 5
    ((request, timeout),) = calls
    # kurze Zeitgrenze je Socket-Operation, damit ein Abbruch binnen 5 s greift (BAUPLAN §6)
    assert timeout == oui.FETCH_TIMEOUT_S and 0 < timeout < 5
    assert request.full_url == OUI_URL  # type: ignore[attr-defined]
    assert request.get_header("User-agent") == "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Netzwerkscanner-OUI-Update"  # type: ignore[attr-defined]


def test_default_fetch_turns_network_errors_into_os_error(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    def fake_urlopen(request, timeout=None):  # type: ignore[no-untyped-def]
        raise urllib.error.URLError("Name or service not known")

    monkeypatch.setattr(oui.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(OSError, match="Herstellerliste konnte nicht geladen werden"):
        update_from_ieee(tmp_path, min_entries=1)
    assert list(tmp_path.iterdir()) == []


def test_default_fetch_rejects_oversized_answer(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(oui, "MAX_DOWNLOAD_BYTES", 100)
    monkeypatch.setattr(oui.urllib.request, "urlopen", lambda request, timeout=None: FakeResponse(b"x" * 500))
    with pytest.raises(ValueError, match="groß"):
        update_from_ieee(tmp_path, min_entries=1)
    assert list(tmp_path.iterdir()) == []
