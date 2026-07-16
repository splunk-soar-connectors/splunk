# Copyright (c) 2016-2026 Splunk Inc.

from src.app import Asset


def test_tls_verification_is_enabled_by_default():
    assert Asset.model_fields["verify_server_cert"].default is True
