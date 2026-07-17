def test_arbiterclient_importable_from_package_root():
    # README and consumers do `from hold_sdk import ArbiterClient`.
    from hold_sdk import ArbiterClient
    assert ArbiterClient.__name__ == "ArbiterClient"
