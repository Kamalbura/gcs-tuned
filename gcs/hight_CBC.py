"""Thin wrapper that delegates HIGHT CBC to the real implementation under drneha/hight."""
try:
    # When running inside the gcs package
    from drneha.hight.hight_CBC import (
        cbc_hight_encryption as _cbc_enc,
        cbc_hight_decryption as _cbc_dec,
    )
except Exception as _e:
    # Fallback if executed in a context where relative path differs
    from drneha.hight.hight_CBC import (
        cbc_hight_encryption as _cbc_enc,
        cbc_hight_decryption as _cbc_dec,
    )


def cbc_hight_encryption(plaintext_bytes, iv, master_key):
    return _cbc_enc(plaintext_bytes, iv, master_key)


def cbc_hight_decryption(ciphertext_bytes, iv, master_key):
    return _cbc_dec(ciphertext_bytes, iv, master_key)
