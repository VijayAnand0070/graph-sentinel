from __future__ import annotations

import gzip
import json
from pathlib import Path

import pyarrow.parquet as pq

from graphsentinel.ingestion.auth import ingest_auth, process_auth_stream
from graphsentinel.ingestion.id_map import AuthIdMaps
from graphsentinel.ingestion.labels import RedTeamIndex


def _write_gzip(path: Path, text: str) -> None:
    with gzip.open(path, "wt", encoding="utf-8", newline="") as stream:
        stream.write(text)


def test_auth_stream_labels_chunks_and_rejects_without_shifting_ids(tmp_path: Path) -> None:
    auth = tmp_path / "auth.txt.gz"
    redteam = tmp_path / "redteam.txt.gz"
    _write_gzip(redteam, "2,U1@D,C1,C3\n")
    _write_gzip(
        auth,
        "1,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Success\n"
        "2,U1@D,U1@D,C1,C3,NTLM,Network,LogOn,Success\n"
        "malformed,row\n"
        "3,U2@D,?,C4,C5,Negotiate,Service,LogOn,Fail\n",
    )
    captured = []

    def writer(events):
        captured.extend(events)
        return 1

    maps = AuthIdMaps()
    stats, writes = process_auth_stream(
        auth,
        RedTeamIndex.from_gzip(redteam),
        maps,
        writer,
        chunk_rows=2,
    )

    assert [event.event_id for event in captured] == [0, 1, 2]
    assert [event.label_redteam for event in captured] == [0, 1, 0]
    assert captured[2].dst_user_id == 0
    assert stats.rows_read == 4
    assert stats.rows_parsed == 3
    assert stats.rows_rejected == 1
    assert stats.redteam_matches == 1
    assert stats.missing_values["dst_user"] == 1
    assert writes == 2


def test_auth_stream_rejects_out_of_order_event(tmp_path: Path) -> None:
    auth = tmp_path / "auth.txt.gz"
    redteam = tmp_path / "redteam.txt.gz"
    _write_gzip(redteam, "5,U9@D,C9,C10\n")
    _write_gzip(
        auth,
        "5,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Success\n"
        "4,U2@D,U2@D,C2,C3,Kerberos,Network,LogOn,Success\n",
    )

    captured = []
    stats, _ = process_auth_stream(
        auth,
        RedTeamIndex.from_gzip(redteam),
        AuthIdMaps(),
        lambda events: captured.extend(events) or 0,
        chunk_rows=10,
    )

    assert len(captured) == 1
    assert stats.rejection_reasons["timestamp_order"] == 1
    assert not stats.timestamps_non_decreasing


def test_auth_stream_sampling_preserves_labels_and_chronology(tmp_path: Path) -> None:
    auth = tmp_path / "auth.txt.gz"
    redteam = tmp_path / "redteam.txt.gz"
    _write_gzip(redteam, "2,U2@D,C2,C3\n")
    _write_gzip(
        auth,
        "1,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Success\n"
        "2,U2@D,U2@D,C2,C3,Kerberos,Network,LogOn,Success\n"
        "3,U3@D,U3@D,C3,C4,Kerberos,Network,LogOn,Success\n"
        "4,U4@D,U4@D,C4,C5,Kerberos,Network,LogOn,Success\n",
    )
    captured = []
    stats, _ = process_auth_stream(
        auth,
        RedTeamIndex.from_gzip(redteam),
        AuthIdMaps(),
        lambda events: captured.extend(events) or 0,
        chunk_rows=10,
        sample_stride=3,
        end_timestamp=3,
    )

    assert [event.timestamp for event in captured] == [1, 2]
    assert [event.label_redteam for event in captured] == [0, 1]
    assert stats.rows_sampled_out == 1


def test_auth_ingestion_persists_parquet_maps_and_report(tmp_path: Path) -> None:
    auth = tmp_path / "auth.txt.gz"
    redteam = tmp_path / "redteam.txt.gz"
    output = tmp_path / "interim"
    maps = tmp_path / "id_maps"
    report_path = tmp_path / "reports" / "auth.json"
    _write_gzip(redteam, "86401,U2@D,C2,C3\n")
    _write_gzip(
        auth,
        "1,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Success\n"
        "86401,U2@D,U2@D,C2,C3,NTLM,Network,LogOn,Success\n",
    )

    report = ingest_auth(
        auth_path=auth,
        redteam_path=redteam,
        output_dir=output,
        id_map_dir=maps,
        report_path=report_path,
        chunk_rows=1,
    )

    parquet_files = sorted(output.rglob("*.parquet"))
    assert report.rows_parsed == 2
    assert report.redteam_matches == 1
    assert report.redteam_unmatched == 0
    assert report.parquet_files == 2
    assert len(parquet_files) == 2
    assert pq.read_table(parquet_files[1]).column("label_redteam").to_pylist() == [1]
    assert (maps / "users.json").is_file()
    assert (maps / "hosts.json").is_file()
    persisted_report = json.loads(report_path.read_text(encoding="utf-8"))
    assert persisted_report["source_auth_sha256"] == report.source_auth_sha256


def test_auth_stream_drops_self_loops_the_gateway_would_refuse(tmp_path: Path) -> None:
    """Local logons (source host == destination host) never reach the live
    gateway, so the offline corpus must not contain them either; they are
    counted, and a labelled one is counted on its own."""
    auth = tmp_path / "auth.txt.gz"
    redteam = tmp_path / "redteam.txt.gz"
    _write_gzip(redteam, "3,U3@D,C3,C3\n4,U4@D,C4,C5\n")
    _write_gzip(
        auth,
        "1,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Success\n"
        "2,C2$@D,C2$@D,C2,C2,Negotiate,Service,LogOn,Success\n"
        "3,U3@D,U3@D,C3,C3,Kerberos,Network,LogOn,Success\n"
        "4,U4@D,U4@D,C4,C5,NTLM,Network,LogOn,Success\n",
    )
    captured = []
    stats, _ = process_auth_stream(
        auth,
        RedTeamIndex.from_gzip(redteam),
        AuthIdMaps(),
        lambda events: captured.extend(events) or 0,
        chunk_rows=10,
    )
    assert [event.timestamp for event in captured] == [1, 4]
    assert all(event.src_host_id != event.dst_host_id for event in captured)
    assert stats.rows_self_loop == 2
    assert stats.redteam_self_loops == 1
    assert stats.redteam_matches == 1
    assert stats.rows_parsed == 2

    kept = []
    stats_kept, _ = process_auth_stream(
        auth,
        RedTeamIndex.from_gzip(redteam),
        AuthIdMaps(),
        lambda events: kept.extend(events) or 0,
        chunk_rows=10,
        drop_self_loops=False,
    )
    assert [event.timestamp for event in kept] == [1, 2, 3, 4]
    assert stats_kept.rows_self_loop == 0


def test_auth_ingestion_report_records_the_self_loop_policy(tmp_path: Path) -> None:
    auth = tmp_path / "auth.txt.gz"
    redteam = tmp_path / "redteam.txt.gz"
    _write_gzip(redteam, "1,U1@D,C1,C2\n")
    _write_gzip(
        auth,
        "1,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Success\n"
        "2,U1@D,U1@D,C1,C1,Kerberos,Network,LogOn,Success\n",
    )
    report = ingest_auth(
        auth_path=auth,
        redteam_path=redteam,
        output_dir=tmp_path / "interim",
        id_map_dir=tmp_path / "id_maps",
        report_path=tmp_path / "auth.json",
        chunk_rows=10,
    )
    assert report.drop_self_loops is True
    assert report.rows_self_loop == 1
    assert report.rows_parsed == 1
    persisted = json.loads((tmp_path / "auth.json").read_text(encoding="utf-8"))
    assert persisted["drop_self_loops"] is True and persisted["rows_self_loop"] == 1
