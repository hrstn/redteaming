# hostpayload (AdaptixPowerShell)

Legacy, frozen PowerShell payload generator. It is runnable but no longer
developed; `modules/` and `tests/` are kept as-is.

Entry point: `python3 payloader.py -h`

This generator has been superseded by
[`hostpayload_v2/`](../hostpayload_v2/README.md), the maintained
harden-delivery generator (native drop-and-stomp droppers, ChaCha20+HMAC,
fetch mode, ISO/LNK/HTA wrappers).

For current v1 usage, see [USAGE.md](USAGE.md).