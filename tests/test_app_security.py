# Copyright (c) 2016-2026 Splunk Inc.

from unittest.mock import Mock

from src import app as app_module
from src.app import Asset, SplunkHelper, escape_spl_string


def test_tls_verification_is_enabled_by_default():
    assert Asset.model_fields["verify_server_cert"].default is True


def test_escape_spl_string_protects_string_literal_boundaries():
    assert escape_spl_string('id" | delete \\ tail') == 'id\\" | delete \\\\ tail'


def test_xml_parser_explicitly_disables_entities(monkeypatch):
    parse = Mock(return_value={"response": {}})
    monkeypatch.setattr(app_module.xmltodict, "parse", parse)
    response = Mock(text="<response />", status_code=200)

    assert SplunkHelper._process_xml_response(response) == {"response": {}}
    parse.assert_called_once_with("<response />", disable_entities=True)
