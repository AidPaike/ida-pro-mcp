"""Tests for agent-oriented debugger event loop helpers."""

import queue
import subprocess

from ..framework import test, assert_shape
from .. import api_dbg_loop


@test()
def test_dbg_loop_event_buffer_returns_events_after_cursor():
    old_seq = api_dbg_loop._EVENT_SEQ
    old_events = list(api_dbg_loop._EVENT_BUF)
    old_hooks = api_dbg_loop._DBG_HOOKS
    try:
        api_dbg_loop._EVENT_BUF.clear()
        api_dbg_loop._EVENT_SEQ = 0

        api_dbg_loop._emit_event("breakpoint", tid=7, ea="0x401000")
        api_dbg_loop._emit_event("exception", tid=7, ea="0x401004")

        assert api_dbg_loop._current_cursor() == 2
        assert api_dbg_loop._copy_events_after(0, 1) == [
            {
                "seq": 1,
                "time": api_dbg_loop._EVENT_BUF[0]["time"],
                "kind": "breakpoint",
                "tid": 7,
                "ea": "0x401000",
            }
        ]
        assert [event["kind"] for event in api_dbg_loop._copy_events_after(1, 10)] == [
            "exception"
        ]
    finally:
        api_dbg_loop._EVENT_BUF.clear()
        api_dbg_loop._EVENT_BUF.extend(old_events)
        api_dbg_loop._EVENT_SEQ = old_seq
        api_dbg_loop._DBG_HOOKS = old_hooks


@test()
def test_dbg_loop_hooks_emit_events():
    """MCPDbgHooks callbacks populate the shared event buffer."""
    old_seq = api_dbg_loop._EVENT_SEQ
    old_events = list(api_dbg_loop._EVENT_BUF)
    old_hooks = api_dbg_loop._DBG_HOOKS
    try:
        api_dbg_loop._EVENT_BUF.clear()
        api_dbg_loop._EVENT_SEQ = 0
        api_dbg_loop._install_dbg_hooks()
        assert api_dbg_loop._DBG_HOOKS is not None

        cursor = api_dbg_loop._current_cursor()
        api_dbg_loop._DBG_HOOKS.dbg_bpt(tid=1234, bptea=0x401000)
        events = api_dbg_loop._copy_events_after(cursor, 10)

        assert len(events) == 1
        assert_shape(
            events[0],
            {
                "seq": int,
                "time": float,
                "kind": "breakpoint",
                "tid": 1234,
                "ea": "0x401000",
            },
        )
    finally:
        if api_dbg_loop._DBG_HOOKS is not None:
            try:
                api_dbg_loop._DBG_HOOKS.unhook()
            except Exception:
                pass
        api_dbg_loop._EVENT_BUF.clear()
        api_dbg_loop._EVENT_BUF.extend(old_events)
        api_dbg_loop._EVENT_SEQ = old_seq
        api_dbg_loop._DBG_HOOKS = old_hooks


@test()
def test_dbg_loop_init_installs_hooks():
    """dbg_loop_init installs the persistent debug event hooks."""
    old_hooks = api_dbg_loop._DBG_HOOKS
    try:
        result = api_dbg_loop.dbg_loop_init()
        assert result["ok"] is True
        assert api_dbg_loop._DBG_HOOKS is not None
    finally:
        if api_dbg_loop._DBG_HOOKS is not None:
            try:
                api_dbg_loop._DBG_HOOKS.unhook()
            except Exception:
                pass
        api_dbg_loop._DBG_HOOKS = old_hooks


@test()
def test_dbg_loop_cleanup_temp_breakpoints_does_not_crash():
    """_cleanup_temp_breakpoints tolerates missing debugger state."""
    old_bps = set(api_dbg_loop._TEMP_BREAKPOINTS)
    try:
        api_dbg_loop._TEMP_BREAKPOINTS.add(0xDEADBEEF)
        api_dbg_loop._cleanup_temp_breakpoints()
        assert api_dbg_loop._TEMP_BREAKPOINTS == set()
    finally:
        api_dbg_loop._TEMP_BREAKPOINTS.clear()
        api_dbg_loop._TEMP_BREAKPOINTS.update(old_bps)


@test()
def test_dbg_pty_session_read_drain_works():
    """_PtySession.read drains queued output and respects timeout."""
    proc = None
    try:
        proc = subprocess.Popen(
            ["python", "-c", "print('line1'); print('line2')"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        stdout_q = queue.Queue()
        stderr_q = queue.Queue()
        session = api_dbg_loop._PtySession(
            process=proc,
            stdout_queue=stdout_q,
            stderr_queue=stderr_q,
            path="python",
            args="",
            start_dir="",
        )
        stdout_q.put(("stdout", b"prequeued"))
        out, err, eof, code = session.read(4096, 100)
        assert out == b"prequeued"
        assert err == b""
        assert not eof
    finally:
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
