from pathlib import Path

from scripts.install_desktop_launcher import install_launcher, make_desktop_entry


def test_desktop_entry_runs_app_in_terminal_and_uses_russian_labels(tmp_path: Path):
    app = tmp_path / "venv with spaces" / "happ-killswitch"
    entry = make_desktop_entry(app, "/usr/bin/gnome-terminal")
    assert "Name=Happ — сетевой выключатель" in entry
    assert 'Exec="/usr/bin/gnome-terminal" -- "' in entry
    assert "Terminal=false" in entry


def test_launcher_installs_per_user_desktop_file(tmp_path: Path):
    app = tmp_path / "happ-killswitch"
    app.write_text("#!/bin/sh\n", encoding="utf-8")
    applications = tmp_path / "applications"

    target = install_launcher(applications, app, "/usr/bin/gnome-terminal")

    assert target.exists()
    assert target.parent == applications
    assert str(app).replace("\\", "\\\\") in target.read_text(encoding="utf-8")
