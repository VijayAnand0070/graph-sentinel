"""Every authentication log format lands on one normalized event.

Each adapter parses its own documented sample and the assertions are on the
edges that come out: who, from where, to where, when, and whether it worked.
Then the generic ingest takes those events through the same interim dataset
the LANL corpus uses, so the rest of the pipeline never sees a format.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pyarrow.parquet as pq
import pytest

from graphsentinel.ingestion.generic import LabelIndex, ingest_logs, normalize_events
from graphsentinel.ingestion.id_map import AuthIdMaps
from graphsentinel.sources import (
    FORMATS,
    ColumnMap,
    EntraSignIns,
    OktaSystemLog,
    ParseStats,
    SSHAuthLog,
    TabularAuthLog,
    WindowsJsonEvents,
    ZeekAuthLog,
    adapter_for,
    parse_timestamp,
    resolve_format,
    sniff,
    sniff_paths,
)
from graphsentinel.sources.detect import UnknownLogFormat, infer_column_map


def _parse(adapter, text: str):  # type: ignore[no-untyped-def]
    stats = ParseStats()
    events = list(adapter.parse(text.splitlines(keepends=True), stats))
    return events, stats


class TestTimestamps:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("2026-03-02T09:14:03Z", 1772442843),
            ("2026-03-02T09:14:03.1234567+00:00", 1772442843),
            ("2026-03-02 09:14:03", 1772442843),
            (1772442843, 1772442843),
            (1772442843123, 1772442843),
            ("1772442843.5", 1772442843),
        ],
    )
    def test_common_shapes(self, value: object, expected: int) -> None:
        assert parse_timestamp(value) == expected

    def test_syslog_needs_a_year(self) -> None:
        assert parse_timestamp("Mar  2 09:16:00") is None
        assert parse_timestamp("Mar  2 09:16:00", assume_year=2026) == 1772442960

    def test_garbage_is_none(self) -> None:
        assert parse_timestamp("yesterday") is None
        assert parse_timestamp(True) is None


class TestSSH:
    def test_sample(self) -> None:
        events, stats = _parse(SSHAuthLog(assume_year=2026), SSHAuthLog.sample)
        assert stats.lines == 5 and stats.events == 4
        assert stats.skipped == {"not_authentication": 1}
        first = events[0]
        assert (first.user, first.source_host, first.destination_host) == (
            "alice",
            "10.0.0.5",
            "WEB01",
        )
        assert (
            first.success and first.auth_type == "ssh-publickey" and first.timestamp == 1772442843
        )
        assert [e.success for e in events] == [True, False, True, False]
        assert events[3].user == "admin" and events[3].source_host == "203.0.113.9"

    def test_year_less_stamp_without_a_year_is_counted(self) -> None:
        events, stats = _parse(SSHAuthLog(), SSHAuthLog.sample)
        assert len(events) == 3 and stats.skipped["year_needed"] == 1


class TestZeek:
    def test_json_sample(self) -> None:
        events, stats = _parse(ZeekAuthLog(), ZeekAuthLog.sample)
        assert stats.events == 3
        tgs, ntlm, tgt = events
        assert (tgs.user, tgs.source_host, tgs.destination_host, tgs.orientation) == (
            "alice@CORP",
            "10.0.0.5",
            "FS01",
            "TGS",
        )
        assert (ntlm.user, ntlm.source_host, ntlm.destination_host, ntlm.success) == (
            "bob@CORP",
            "WS07",
            "DB01",
            False,
        )
        assert tgt.destination_host == "10.0.0.2" and tgt.orientation == "TGT"

    def test_tsv_with_fields_header(self) -> None:
        text = (
            "#separator \\x09\n#path\tntlm\n"
            "#fields\tts\tid.orig_h\tid.resp_h\tusername\thostname\tdomainname\t"
            "server_nb_computer_name\tsuccess\n"
            "1772442880.0\t10.0.0.7\t10.0.0.9\tbob\tWS07\tCORP\tDB01\tT\n"
            "1772442881.0\t10.0.0.7\t10.0.0.9\tbob\tWS07\tCORP\tWS07\tT\n"
        )
        events, stats = _parse(ZeekAuthLog(), text)
        assert len(events) == 1 and events[0].success is True
        assert stats.skipped == {"self_loop": 1}


class TestCloud:
    def test_entra_sample(self) -> None:
        events, stats = _parse(EntraSignIns(), EntraSignIns.sample)
        assert stats.events == 2
        ok, bad = events
        assert (ok.user, ok.source_host, ok.destination_host, ok.success) == (
            "alice@CORP",
            "WS05",
            "SHAREPOINT ONLINE",
            True,
        )
        assert (bad.source_host, bad.success) == ("203.0.113.9", False)

    def test_entra_graph_envelope(self) -> None:
        lines = EntraSignIns.sample.splitlines()
        envelope = json.dumps({"value": [json.loads(line) for line in lines]}, indent=1)
        events, _ = _parse(EntraSignIns(), envelope)
        assert len(events) == 2

    def test_okta_sample(self) -> None:
        events, stats = _parse(OktaSystemLog(), OktaSystemLog.sample)
        assert stats.events == 3
        session, sso, failed = events
        assert session.destination_host == "OKTA" and session.success
        assert sso.destination_host == "SALESFORCE" and sso.auth_type == "sso"
        assert failed.success is False and failed.source_host == "203.0.113.9"


class TestWindowsJson:
    def test_sample(self) -> None:
        events, stats = _parse(WindowsJsonEvents(), WindowsJsonEvents.sample)
        assert stats.lines == 4 and stats.events == 3
        assert stats.skipped == {"not_authentication": 1}
        logon, ticket, failure = events
        assert (logon.user, logon.source_host, logon.destination_host) == (
            "alice@CORP",
            "WS05",
            "FS01",
        )
        assert logon.auth_type == "Kerberos" and logon.logon_type == "Network"
        assert ticket.orientation == "TGS" and ticket.destination_host == "FS01"
        assert failure.success is False and failure.auth_type == "NTLM"

    def test_winlogbeat_shape(self) -> None:
        record = {
            "@timestamp": "2026-03-02T09:14:03.000Z",
            "winlog": {
                "event_id": 4624,
                "computer_name": "fs01.corp.example",
                "event_data": {
                    "TargetUserName": "alice",
                    "TargetDomainName": "CORP",
                    "WorkstationName": "WS05",
                    "LogonType": "3",
                    "AuthenticationPackageName": "Kerberos",
                },
            },
        }
        events, _ = _parse(WindowsJsonEvents(), json.dumps(record) + "\n")
        assert len(events) == 1 and events[0].destination_host == "FS01"


class TestTabular:
    def test_sample(self) -> None:
        adapter = TabularAuthLog(ColumnMap.parse(TabularAuthLog.sample_map))
        events, stats = _parse(adapter, TabularAuthLog.sample)
        assert stats.events == 3
        assert [e.success for e in events] == [True, False, True]
        assert events[0].user == "alice@CORP" and events[0].auth_type == "Kerberos"

    def test_json_lines(self) -> None:
        adapter = TabularAuthLog(
            ColumnMap.parse("timestamp=t,user=u,source_host=s,destination_host=d,success=ok")
        )
        text = '{"t": 1772442843, "u": "alice", "s": "WS05", "d": "FS01", "ok": "yes"}\n'
        events, _ = _parse(adapter, text)
        assert len(events) == 1 and events[0].success

    def test_map_validation(self) -> None:
        with pytest.raises(ValueError, match="required"):
            ColumnMap.parse("timestamp=t,user=u")
        with pytest.raises(ValueError, match="unknown field"):
            ColumnMap.parse("timestamp=t,user=u,source_host=s,destination_host=d,colour=c")


class TestRegistry:
    def test_every_format_parses_its_own_sample(self) -> None:
        for name in FORMATS:
            kwargs = {"column_map": TabularAuthLog.sample_map} if name == "tabular" else {}
            adapter = adapter_for(name, assume_year=2026, **kwargs)
            events, stats = _parse(adapter, adapter.sample)
            assert events, name
            assert stats.events == len(events), name
            assert all(not e.is_self_loop for e in events), name

    def test_unknown_format_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unknown source format"):
            adapter_for("syslog-of-my-dreams")


class TestGenericIngest:
    def test_normalize_sorts_dedupes_and_labels(self) -> None:
        events, _ = _parse(SSHAuthLog(assume_year=2026), SSHAuthLog.sample)
        shuffled = [events[2], events[0], events[1], events[1], events[3]]
        labels = LabelIndex(frozenset({events[2].key()}), rows=1)
        normalized, counts = normalize_events(shuffled, AuthIdMaps(), labels=labels)
        assert [n.timestamp for n in normalized] == sorted(n.timestamp for n in normalized)
        assert counts["duplicates"] == 1 and counts["labels_matched"] == 1
        assert [n.label_redteam for n in normalized] == [0, 0, 1, 0]
        assert [n.event_id for n in normalized] == [0, 1, 2, 3]

    def test_ingest_logs_end_to_end(self, tmp_path: Path) -> None:
        log = tmp_path / "auth.log.gz"
        with gzip.open(log, "wt", encoding="utf-8") as handle:
            handle.write(SSHAuthLog.sample)
        labels = tmp_path / "labels.csv"
        labels.write_text(
            "time,user,src_host,dst_host\n1772442901,bob,10.0.0.7,DB01\n", encoding="utf-8"
        )
        report = ingest_logs(
            format_name="ssh-auth",
            inputs=[log],
            output_dir=tmp_path / "interim",
            id_map_dir=tmp_path / "id_maps",
            report_path=tmp_path / "report.json",
            labels_path=labels,
            assume_year=2026,
        )
        assert report.format == "ssh-auth" and report.rows_parsed == 4
        assert report.labels_matched == 1 and report.redteam_matches == 1
        assert report.unique_counts["users"] == 3 and report.unique_counts["hosts"] >= 5
        files = sorted((tmp_path / "interim").rglob("*.parquet"))
        assert files and report.parquet_files == len(files)
        table = pq.read_table(files[0])
        assert "label_redteam" in table.column_names
        assert (tmp_path / "id_maps" / "users.json").is_file()
        persisted = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
        assert (
            persisted["drop_self_loops"] is True and persisted["timestamps_non_decreasing"] is True
        )

    def test_ingest_refuses_an_empty_source(self, tmp_path: Path) -> None:
        log = tmp_path / "auth.log"
        log.write_text("nothing here\n", encoding="utf-8")
        with pytest.raises(ValueError, match="no authentication events"):
            ingest_logs(
                format_name="ssh-auth",
                inputs=[log],
                output_dir=tmp_path / "i",
                id_map_dir=tmp_path / "m",
                report_path=tmp_path / "r.json",
            )


class TestFormatDetection:
    """`--format auto`: the operator has a file, not a format name."""

    def test_every_adapter_recognises_its_own_sample(self) -> None:
        for name, adapter_class in (
            ("windows-json", WindowsJsonEvents),
            ("ssh-auth", SSHAuthLog),
            ("zeek", ZeekAuthLog),
            ("entra-signin", EntraSignIns),
            ("okta", OktaSystemLog),
            ("tabular", TabularAuthLog),
        ):
            detection = sniff(adapter_class.sample.splitlines(keepends=True))
            assert detection.format == name, (name, detection)
            assert detection.confidence >= 0.6, (name, detection.confidence)
            assert detection.reasons, name

    def test_the_tabular_sample_infers_its_documented_map(self) -> None:
        detection = sniff(TabularAuthLog.sample.splitlines(keepends=True))
        assert detection.column_map is not None
        # The map the adapter documents by hand, arrived at without being told.
        for pair in (
            "timestamp=event_time",
            "user=account",
            "source_host=client",
            "destination_host=server",
        ):
            assert pair in detection.column_map

    def test_a_bespoke_export_nobody_wrote_an_adapter_for(self) -> None:
        csv_text = (
            "Event Time,User Principal,Client Workstation,Target Server,Auth Result,Protocol\n"
            "2026-03-02T09:14:03Z,alice@corp.example,WS05,FS01,ALLOW,Kerberos\n"
            "2026-03-02T09:15:00Z,bob@corp.example,WS07,DB01,DENY,NTLM\n"
        )
        detection = sniff(csv_text.splitlines(keepends=True))
        assert detection.format == "tabular"
        assert detection.fields["source_host"] == "Client Workstation"
        assert detection.fields["destination_host"] == "Target Server"
        # And the inferred map actually reads the file.
        adapter = adapter_for("tabular", column_map=detection.column_map)
        events, _stats = _parse(adapter, csv_text)
        assert [(e.user, e.source_host, e.destination_host, e.success) for e in events] == [
            ("alice@CORP", "WS05", "FS01", True),
            ("bob@CORP", "WS07", "DB01", False),
        ]

    def test_source_and_destination_are_not_decided_by_column_order(self) -> None:
        # Both columns end in the same noun; only the qualifier separates them,
        # and a first-come match would put the source in the destination.
        fields, _warnings = infer_column_map(
            ["@timestamp", "account_name", "dest_machine", "src_machine", "status"]
        )
        assert fields["source_host"] == "src_machine"
        assert fields["destination_host"] == "dest_machine"

    def test_a_success_column_the_parser_cannot_read_is_a_warning(self) -> None:
        text = (
            "ts,user,src,dst,verdict\n"
            "2026-03-02T09:14:03Z,alice,WS05,FS01,PASSED\n"
            "2026-03-02T09:15:03Z,alice,WS05,DB01,BLOCKED\n"
        )
        detection = sniff(text.splitlines(keepends=True))
        assert detection.format == "tabular"
        assert detection.fields["success"] == "verdict"
        assert any("reads as success" in w for w in detection.warnings), detection.warnings

    def test_a_log_with_no_outcome_column_says_so(self) -> None:
        # Without one the adapter records every event as a success -- and the
        # chain rule counts successful hops, so this must not pass in silence.
        text = (
            "ts,user,src,dst\n"
            "2026-03-02T09:14:03Z,alice,WS05,FS01\n"
            "2026-03-02T09:15:03Z,alice,FS01,DB01\n"
        )
        detection = sniff(text.splitlines(keepends=True))
        assert "success" not in detection.fields
        assert any("recorded as a success" in w for w in detection.warnings), detection.warnings

    def test_a_log_with_no_destination_column_is_refused_by_name(self) -> None:
        text = "when,who,result\n2026-03-02T09:14:03Z,alice,SUCCESS\n"
        with pytest.raises(UnknownLogFormat, match="destination_host"):
            sniff(text.splitlines(keepends=True))

    def test_something_that_is_not_a_log_at_all_is_refused(self) -> None:
        with pytest.raises(UnknownLogFormat, match="nothing in the sample"):
            sniff(["the quick brown fox\n", "jumped over the lazy dog\n"])
        with pytest.raises(UnknownLogFormat, match="empty"):
            sniff([])

    def test_mixed_formats_in_one_ingest_are_refused(self, tmp_path: Path) -> None:
        ssh = tmp_path / "auth.log"
        ssh.write_text(SSHAuthLog.sample, encoding="utf-8")
        okta = tmp_path / "okta.json"
        okta.write_text(OktaSystemLog.sample, encoding="utf-8")
        with pytest.raises(UnknownLogFormat, match="one format at a time"):
            sniff_paths([ssh, okta])

    def test_auto_ingests_a_format_the_operator_never_named(self, tmp_path: Path) -> None:
        log = tmp_path / "siem-export.jsonl"
        log.write_text(
            '{"@timestamp":"2026-03-02T09:14:03Z","account_name":"alice@corp.example",'
            '"src_machine":"WS05","dest_machine":"FS01","status":"success"}\n'
            '{"@timestamp":"2026-03-02T09:15:00Z","account_name":"bob@corp.example",'
            '"src_machine":"WS07","dest_machine":"DB01","status":"failure"}\n',
            encoding="utf-8",
        )
        report = ingest_logs(
            format_name="auto",
            inputs=[log],
            output_dir=tmp_path / "interim",
            id_map_dir=tmp_path / "id_maps",
            report_path=tmp_path / "report.json",
        )
        assert report.format == "tabular" and report.rows_parsed == 2
        assert report.success_values == {"Success": 1, "Fail": 1}
        # The guess, and what it rested on, travel with the dataset.
        assert report.detection is not None
        assert report.detection["fields"]["destination_host"] == "dest_machine"
        assert any("detected automatically" in note for note in report.notes)

    def test_an_explicit_map_is_never_second_guessed(self, tmp_path: Path) -> None:
        log = tmp_path / "export.csv"
        log.write_text(
            "ts,user,src,dst,status\n2026-03-02T09:14:03Z,alice,WS05,FS01,SUCCESS\n",
            encoding="utf-8",
        )
        chosen = "timestamp=ts,user=user,source_host=dst,destination_host=src"
        name, column_map, detection = resolve_format("auto", [log], column_map=chosen)
        assert name == "tabular" and column_map == chosen
        # The detection is still reported, so a disagreement is visible.
        assert detection is not None and detection.column_map != chosen
