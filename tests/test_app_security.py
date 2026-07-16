# Copyright (c) 2016-2026 Splunk Inc.

from src.app import Asset, escape_spl_string


def test_tls_verification_is_enabled_by_default():
    assert Asset.model_fields["verify_server_cert"].default is True


def test_escape_spl_string_protects_string_literal_boundaries():
    assert escape_spl_string('id" | delete \\ tail') == 'id\\" | delete \\\\ tail'
