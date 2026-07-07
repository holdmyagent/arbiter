def test_trusted_proxies_defaults_empty_and_loads(tmp_path):
    from arbiter.config import Config
    c = Config.load(str(tmp_path / "absent.toml"))
    assert c.server.trusted_proxies == []
    p = tmp_path / "c.toml"
    p.write_text('[server]\ntrusted_proxies = ["10.0.0.0/8", "127.0.0.1/32"]\n')
    c2 = Config.load(str(p))
    assert c2.server.trusted_proxies == ["10.0.0.0/8", "127.0.0.1/32"]
