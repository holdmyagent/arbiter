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

def test_open_cell_wires_per_cell_delivery(tmp_path):
    """§9 at the real wiring point: open_cell must feed each cell's Dispatcher
    the PER-CELL delivery config, never the process cfg's sinks."""
    from arbiter.registry import open_cell
    cfg = Config.load(str(tmp_path / "absent.toml"))
    cfg.webhook.url = "https://proc.example/hook"
    cfg.callback_allowlist = ["https://proc.example/*"]
    class S:  # sentinel sender
        pass
    s = S()

    bdir = (tmp_path / "cells" / "b").resolve()
    bdir.mkdir(parents=True)
    (bdir / "notify.toml").write_text(
        '[webhook]\nurl = "https://b.example/hook"\n'
        '[notify]\ncallback_allowlist = ["https://b.example/*"]\n')
    cell_b = open_cell("b", bdir, 1, cfg, sender=s)
    assert cell_b.dispatcher.cfg.webhook.url == "https://b.example/hook"
    assert cell_b.dispatcher.cfg.callback_allowlist == ["https://b.example/*"]
    assert cell_b.dispatcher.sender is s

    cdir = (tmp_path / "cells" / "c").resolve()
    cdir.mkdir(parents=True)
    cell_c = open_cell("c", cdir, 1, cfg, sender=s, other_open_dirs=(bdir,))
    assert cell_c.dispatcher.cfg.webhook.enabled is False   # safe fallback: no egress
    assert cell_c.dispatcher.cfg.callback_allowlist == []
    assert cell_c.dispatcher.cfg is not cell_b.dispatcher.cfg  # no sink sharing

def test_build_cell_dispatcher_uses_passed_sender_and_db(tmp_path):
    cfg = Config.load(str(tmp_path / "absent.toml"))
    db = Database(":memory:")
    class S:  # sentinel sender
        pass
    s = S()
    disp = build_cell_dispatcher(CellDelivery.from_process(cfg), db, s)
    assert disp.db is db and disp.sender is s
