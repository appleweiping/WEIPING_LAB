import asyncio

from cli import monitor


class _FakeProcess:
    stdout = None
    stderr = None

    async def wait(self):
        return 0

    def kill(self):
        return None


def test_windows_monitor_requests_no_console_window(monkeypatch):
    captured = {}

    async def fake_create_subprocess_shell(*args, **kwargs):
        captured.update(kwargs)
        return _FakeProcess()

    monkeypatch.setattr(monitor.asyncio, "create_subprocess_shell", fake_create_subprocess_shell)
    monkeypatch.setattr(monitor.sys, "platform", "win32")

    async def run():
        instance = await monitor.monitor_start("python -c pass")
        await asyncio.sleep(0)
        return instance

    instance = asyncio.run(run())

    assert captured["shell"] is True
    assert captured["creationflags"] == getattr(monitor.subprocess, "CREATE_NO_WINDOW", 0)
    assert instance.exit_code == 0
    monitor.monitor_clear()
