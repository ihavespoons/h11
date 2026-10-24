"""Keep the documented fuzzing chunk-boundary property in the test suite."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import pytest

from .._connection import Connection, NEED_DATA, PAUSED
from .._events import ConnectionClosed, Event
from .._state import SERVER
from .._util import RemoteProtocolError
from .helpers import normalize_data_events


def parse_chunks(chunks: Iterable[bytes]) -> tuple[str, list[Event]]:
    connection = Connection(SERVER)
    events: list[Event] = []

    def drain() -> None:
        while True:
            event = connection.next_event()
            if event is NEED_DATA or event is PAUSED or type(event) is ConnectionClosed:
                return
            events.append(event)

    try:
        for chunk in chunks:
            connection.receive_data(chunk)
            drain()
        connection.receive_data(b"")
        drain()
    except RemoteProtocolError:
        return "protocol_error", []
    return "accepted", normalize_data_events(events)


@pytest.mark.parametrize("seed", ["1", "2", "3", "4"])
def test_fuzz_seed_events_ignore_chunk_boundaries(seed: str) -> None:
    corpus = Path(__file__).resolve().parents[2] / "fuzz" / "afl-server-examples"
    data = (corpus / seed).read_bytes()
    assert parse_chunks([data]) == parse_chunks(data[index:index + 1] for index in range(len(data)))
