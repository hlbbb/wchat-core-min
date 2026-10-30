from __future__ import annotations

from wchat_core.content import (
    base_local_type,
    decode_message_content,
    parse_app_message,
    strip_sender_prefix,
)
from wchat_core.contacts import contact_display_name


def test_base_local_type_handles_wechat_4_high_bits() -> None:
    assert base_local_type(25769803825) == 49
    assert base_local_type(1) == 1


def test_strip_sender_prefix() -> None:
    assert strip_sender_prefix("wxid_x:\nhello", "wxid_x") == "hello"
    assert strip_sender_prefix("hello", "wxid_x") == "hello"


def test_parse_app_message() -> None:
    payload = """<msg><appmsg><title>report.html</title><type>6</type>
    <appattach><totallen>123</totallen><fileext>html</fileext></appattach>
    </appmsg></msg>"""
    parsed = parse_app_message(payload)
    assert parsed["kind"] == "file"
    assert parsed["title"] == "report.html"
    assert parsed["file_ext"] == "html"
    assert parsed["file_size"] == 123


def test_contact_display_name_prefers_remark() -> None:
    assert (
        contact_display_name(
            {"remark": "备注", "nick_name": "昵称", "alias": "alias", "username": "wxid"}
        )
        == "备注"
    )


def test_decode_plain_text() -> None:
    assert decode_message_content(None, "hello") == "hello"
