from __future__ import annotations

import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from wchat_core.content import parse_media_refs
from wchat_core import image_keys
from wchat_core.image_keys import (
    TemplateScanResult,
    V2Template,
    derive_image_keys,
    resolve_image_keys,
)
from wchat_core.media import MediaKeys, decrypt_wechat_dat


def test_parse_file_media_refs() -> None:
    payload = """
    <msg><appmsg><md5>0123456789abcdef0123456789abcdef</md5>
    <appattach><attachid>attachment-id</attachid></appattach>
    </appmsg></msg>
    """
    assert parse_media_refs(payload, "file") == {
        "md5": "0123456789abcdef0123456789abcdef",
        "file_id": "attachment-id",
    }


def test_parse_image_media_refs() -> None:
    payload = '<msg><img md5="fedcba9876543210fedcba9876543210"/></msg>'
    assert parse_media_refs(payload, "image") == {
        "md5": "fedcba9876543210fedcba9876543210"
    }


def test_decrypt_wechat_dat_v2() -> None:
    payload = b"\x89PNG\r\n\x1a\n" + b"fixture" * 4
    padding = 16 - len(payload) % 16
    padded = payload + bytes([padding]) * padding
    aes_key = b"1234567890abcdef"
    encryptor = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    dat = (
        b"\x07\x08V2\x08\x07"
        + struct.pack("<LLx", len(payload), 0)
        + encrypted
    )

    decrypted = decrypt_wechat_dat(
        dat,
        MediaKeys(xor_key=0xA5, aes_key=aes_key),
    )

    assert decrypted == payload


def test_resolve_image_keys_uses_verified_local_template(monkeypatch) -> None:
    code = 0x1234
    wxid = "wxid_example"
    derived = derive_image_keys(code, wxid)
    plaintext = b"\xff\xd8\xff" + (b"\x00" * 13)
    encryptor = Cipher(
        algorithms.AES(derived.aes_key.encode("ascii")),
        modes.ECB(),
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tail = bytes((derived.xor_key ^ 0xFF, derived.xor_key ^ 0xD9))
    scan = TemplateScanResult(
        templates=(
            V2Template(
                path=Path("template_t.dat"),
                ciphertext=ciphertext,
                mtime_ns=1,
                tail_xor_key=derived.xor_key,
                tail_bytes=tail,
            ),
        ),
        inferred_xor_key=derived.xor_key,
        xor_support=1,
    )

    monkeypatch.setattr(image_keys, "scan_v2_templates", lambda *_args, **_kwargs: scan)
    monkeypatch.setattr(
        image_keys,
        "find_kvcomm_dirs",
        lambda *_args, **_kwargs: (Path("kvcomm"),),
    )
    monkeypatch.setattr(
        image_keys,
        "enumerate_kvcomm_codes",
        lambda *_args, **_kwargs: (code,),
    )

    result = resolve_image_keys(
        account_dir=Path("wxid_example_abcd"),
        source_root=None,
        account=wxid,
    )

    assert result is not None
    assert result.xor_key == derived.xor_key
    assert result.aes_key == derived.aes_key
