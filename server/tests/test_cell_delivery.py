from arbiter.config import Config
from arbiter.notify import CellDelivery, cell_delivery, build_cell_dispatcher
from arbiter.db import Database

def test_default_cell_inherits_process_delivery(tmp_path):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    cfg.webhook.url = "https://proc.example/hook"
    cfg.callback_allowlist = ["https://proc.example/*"]
    d = cell_delivery(cfg, "default", tmp_path / "cells" / "default")
    assert d.webhook.url == "https://proc.example/hook"
    assert d.callback_allowlist == ["https://proc.example/*"]

def test_nondefault_cell_reads_own_notify_toml(tmp_path):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    cfg.webhook.url = "https://proc.example/hook"          # process default MUST NOT leak into tenant B
    cdir = tmp_path / "cells" / "b"
    cdir.mkdir(parents=True)
    (cdir / "notify.toml").write_text(
        '[webhook]\nurl = "https://b.example/hook"\n'
        '[notify]\ncallback_allowlist = ["https://b.example/*"]\n')
    d = cell_delivery(cfg, "b", cdir)
    assert d.webhook.url == "https://b.example/hook"
    assert d.callback_allowlist == ["https://b.example/*"]

def test_nondefault_cell_no_config_has_no_egress(tmp_path):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    cfg.webhook.url = "https://proc.example/hook"
    cdir = tmp_path / "cells" / "c"; cdir.mkdir(parents=True)
    d = cell_delivery(cfg, "c", cdir)
    assert d.webhook.enabled is False and d.callback_allowlist == []

def test_build_cell_dispatcher_uses_passed_sender_and_db(tmp_path):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    db = Database(":memory:")
    class S:  # sentinel sender
        pass
    s = S()
    disp = build_cell_dispatcher(CellDelivery.from_process(cfg), db, s)
    assert disp.db is db and disp.sender is s
