from pathlib import Path

from happ_killswitch.watchdog import TunLossGuard, tun_exists


def test_tun_presence_can_be_checked_without_root(tmp_path: Path):
    assert not tun_exists("happ0", tmp_path)
    (tmp_path / "happ0").mkdir()
    assert tun_exists("happ0", tmp_path)


def test_watchdog_locks_only_after_consecutive_absence():
    guard = TunLossGuard(3)
    assert not guard.observe(False)
    assert not guard.observe(True)
    assert not guard.observe(False)
    assert not guard.observe(False)
    assert guard.observe(False)


def test_watchdog_rejects_zero_threshold():
    try:
        TunLossGuard(0)
    except ValueError as exc:
        assert "положительным" in str(exc)
    else:
        raise AssertionError("expected invalid threshold to fail")
