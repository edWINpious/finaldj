"""Collector main loop: tail -> parse -> normalize -> detect -> store -> deliver."""

from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from cowrie_soc.config import Config
from cowrie_soc.detection import DetectionEngine
from cowrie_soc.encoders import make_encoder
from cowrie_soc.normalize import NormalizeConfig, normalize
from cowrie_soc.parser import ParsedEvent, ParseError, RawLine, parse_line
from cowrie_soc.sinks import Deliverer, HttpSink, JsonlSink, Sink
from cowrie_soc.store import Store
from cowrie_soc.tailer import LogFollower

log = logging.getLogger(__name__)

STREAM = "cowrie-json"


@dataclass
class Processed:
    records: list[dict[str, Any]]
    quarantined: list[ParseError]


class Processor:
    """Stateless-per-line processing plus the stateful detection engine."""

    def __init__(self, cfg: Config) -> None:
        self.norm_cfg = NormalizeConfig(
            sensor_id=cfg.collector.sensor_id,
            include_passwords=cfg.normalize.include_passwords,
            max_field_chars=cfg.normalize.max_field_chars,
            scenario_id=cfg.collector.scenario_id or None,
        )
        self.engine = DetectionEngine(cfg.detection, cfg.collector.sensor_id, user_homes=cfg.user_homes)
        self.counters: Counter[str] = Counter()

    def process(self, lines: Iterable[RawLine]) -> Processed:
        records: list[dict[str, Any]] = []
        quarantined: list[ParseError] = []
        for raw in lines:
            parsed = parse_line(raw)
            if parsed is None:
                self.counters["blank"] += 1
                continue
            if isinstance(parsed, ParseError):
                self.counters["quarantined"] += 1
                log.warning("quarantined %s@%d: %s", parsed.source, parsed.offset, parsed.reason)
                quarantined.append(parsed)
                continue
            assert isinstance(parsed, ParsedEvent)
            try:
                event = normalize(parsed, self.norm_cfg)
                findings = self.engine.process(event)
            except Exception as exc:  # noqa: BLE001 - one bad line must not stall the whole stream
                # Quarantine instead of raising: a raise would make step() re-read the whole batch,
                # double-counting detection state for the lines before this one.
                self.counters["quarantined"] += 1
                log.exception("processing failed for %s@%d; quarantined", parsed.source, parsed.offset)
                quarantined.append(ParseError(f"processing error: {type(exc).__name__}: {exc}"[:500],
                                              parsed.source, parsed.offset, parsed.raw_text[:512], parsed.raw_sha256))
                continue
            records.append(event)
            self.counters["events"] += 1
            for finding in findings:
                self.counters["findings"] += 1
                log.info("finding %s %s: %s", finding["severity"].upper(), finding["rule_id"], finding["title"])
                records.append(finding)
        return Processed(records, quarantined)


def build_sinks(cfg: Config) -> list[Sink]:
    sinks: list[Sink] = []
    if cfg.jsonl.enabled:
        sinks.append(JsonlSink(cfg.jsonl.path, cfg.jsonl.max_bytes))
    if cfg.http.enabled:
        encoder = make_encoder(cfg.http.payload_format, cfg.collector.sensor_id, cfg.http.field_map)
        sinks.append(
            HttpSink(
                cfg.http.url, encoder, token_env=cfg.http.token_env, timeout=cfg.http.timeout_seconds,
                batch_size=cfg.http.batch_size, verify_tls=cfg.http.verify_tls, extra_headers=cfg.http.headers,
            )
        )
    return sinks


class Pipeline:
    def __init__(self, cfg: Config, store: Store | None = None, sinks: list[Sink] | None = None) -> None:
        self.cfg = cfg
        self.store = store or Store(cfg.collector.state_db)
        self.follower = LogFollower(
            cfg.source.log_dir,
            cfg.source.base_name,
            start_at_end=cfg.source.start_position == "end",
            max_line_bytes=cfg.source.max_line_bytes,
        )
        self.processor = Processor(cfg)
        self.deliverers = [Deliverer(s, self.store) for s in (sinks if sinks is not None else build_sinks(cfg))]
        self.checkpoint = self.store.load_checkpoint(STREAM)
        self.backpressure = False
        self._stop = threading.Event()

    def step(self) -> int:
        """One iteration: ingest one batch (unless backpressured) and deliver. Returns lines read."""
        pending = self.store.pending_count() if self.deliverers else 0
        if pending >= self.cfg.collector.max_pending_records:
            if not self.backpressure:
                log.warning("backpressure: %d undelivered records >= max_pending_records; pausing ingestion "
                            "(Cowrie keeps logging to disk, nothing is lost)", pending)
            self.backpressure = True
            self._deliver()
            return 0
        if self.backpressure:
            log.info("backpressure released (%d pending)", pending)
            self.backpressure = False

        result = self.follower.poll(self.checkpoint, self.cfg.source.batch_max_lines)
        for _ in range(3):
            # A poll that only moved the checkpoint (first start, rotation switch) is followed
            # immediately by a read of the new position instead of waiting a poll interval.
            if result.lines or result.checkpoint == self.checkpoint or result.checkpoint is None:
                break
            nxt = self.follower.poll(result.checkpoint, self.cfg.source.batch_max_lines)
            nxt.notices[:0] = result.notices
            result = nxt
        for notice in result.notices:
            (log.error if "DATA LOSS" in notice else log.info)("tailer: %s", notice)
        processed = self.processor.process(result.lines)
        if result.lines or result.checkpoint != self.checkpoint:
            commit = self.store.commit(STREAM, result.checkpoint, processed.records, processed.quarantined)
            if commit.duplicates:
                self.processor.counters["duplicates"] += commit.duplicates
                log.info("skipped %d duplicate records already in outbox", commit.duplicates)
            self.checkpoint = result.checkpoint
        self._deliver()
        return len(result.lines)

    def _deliver(self) -> None:
        for d in self.deliverers:
            d.deliver()
        self.store.prune_delivered(self.cfg.collector.retain_delivered_records)

    def run_forever(self) -> None:
        log.info("collector started: log_dir=%s sensor_id=%s sinks=%s checkpoint=%s",
                 self.cfg.source.log_dir, self.cfg.collector.sensor_id,
                 [d.sink.name for d in self.deliverers], self.checkpoint)
        last_report = 0.0
        while not self._stop.is_set():
            try:
                read = self.step()
            except Exception:  # keep running; state is only advanced on successful commits
                log.exception("pipeline step failed; retrying")
                read = 0
            now = time.monotonic()
            if now - last_report > 60:
                last_report = now
                log.info("stats %s pending=%d", dict(self.processor.counters), self.store.pending_count())
            if read < self.cfg.source.batch_max_lines:
                self._stop.wait(self.cfg.source.poll_interval_seconds)
        self._deliver()
        log.info("collector stopped; final stats %s", dict(self.processor.counters))

    def stop(self) -> None:
        self._stop.set()


def replay(lines: Iterable[RawLine], cfg: Config) -> Iterator[dict[str, Any] | ParseError]:
    """Process lines without any state store (used by `cowrie-soc replay` and tests)."""
    processor = Processor(cfg)
    for raw in lines:
        out = processor.process([raw])
        yield from out.quarantined
        yield from out.records
