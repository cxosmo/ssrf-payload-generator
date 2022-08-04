# ssrf-payload-generator
SSRF payload generator which takes an IPv4 address as input and outputs notation variants of that same address (e.g. shorthand notation, decimal etc). Other features include:
- Generation of bypass/redirection-related SSRF payloads using an expected allow-listed domain (`-a`) as input. This is default behaviour which can be supressed via the `-nB` (`--no_bypasses`) flag.
- Generate payloads with less-common URI schemes (`-sG`) [using irsdl's source of Windows-centric schemes](https://github.com/irsdl/OutlookLeakTest), [IANA official schemes](https://www.iana.org/assignments/uri-schemes) and [unofficial-but-seen URIs referenced here](https://en.wikipedia.org/wiki/List_of_URI_schemes).
- Include common cloud-related endpoints in payload outputs (using [cujanovic's curated cloud-metadata.txt list](https://github.com/cujanovic/SSRF-Testing/blob/master/cloud-metadata.txt)), even if unrelated to original IP address input.

# Usage
Basic usage is as follows:

```bash
./ssrf-payload-generator.py -i http://127.0.0.1 -a allowed-domain.example.com
```

*The `--cloud_payloads` (`-cP`) and `--scheme_generation` (`-sG`) features depend on files included in this script's root directory (`cloud-payloads.txt` and `schemes.txt`).*

# Thanks
Huge thanks to cujanovic for their [excellent SSRF-Testing repository](https://github.com/cujanovic/SSRF-Testing); this tool builds upon the [ip.py](https://github.com/cujanovic/SSRF-Testing/blob/master/ip.py) script and other references from that repo.