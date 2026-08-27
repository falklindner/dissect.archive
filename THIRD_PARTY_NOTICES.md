# Third-party notices

`dissect.archive` is licensed under AGPL-3.0-or-later (see `LICENSE` and `COPYRIGHT`).

The TIBX ("archive3") parser in `dissect/archive/tibx/` is a clean reimplementation in
Dissect idioms — no third-party code is vendored — but the format knowledge and the
structure of several algorithms derive from the two MIT-licensed projects below. Their
licenses require that the following notices be preserved.

## acronis-tib-reader ("tibread")

MIT License, Copyright (c) 2026 the tibread contributors
<https://github.com/TreadingTheTiber/acronis-tib-reader>

The LSM index engine and the layers built on it. Derived work, by module:

- `dissect/archive/tibx/lsm.py` — L-SB superblock parsing, the ARCH TLV directory,
  LEAF/LDIR page framing and the cell-stream grammar (`tibread/tibx/lsm.py`,
  `tibread/tibx/lsm_cells.py`)
- `dissect/archive/tibx/maps.py` — `data_map` extent decoding and `segment_map`
  index construction (`tibread/tibx/data_map.py`, `tibread/tibx/segment_map.py`)
- `dissect/archive/tibx/segment.py` — SG segment header parsing and segment
  decompression (`tibread/tibx/segment.py`)
- `dissect/archive/tibx/crypto.py` — the wrapped-key blob layout, KEK derivation and
  segment decryption (`tibread/tibx/encryption.py`)

## acronis-tibx

MIT License, Copyright (c) 2026 mniedermaier

A research project by mniedermaier that is no longer publicly available. It vendored the
`tibread` engine above and built a container layer, codecs and tooling on top. Derived
work, by module:

- `dissect/archive/tibx/c_tibx.py` — the format findings that the structure definitions
  encode
- `dissect/archive/tibx/page.py` — the 4 KiB page store and superblock/commit-root model
  (`tibx/container.py`)
- `dissect/archive/tibx/codecs.py` — the zstd frame, linked-LZ4 and LSM cell-stream
  decoders (`tibx/codecs.py`)
- `dissect/archive/tibx/crypto.py` — the SE header and password-to-data-key flow
  (`tibx/crypto.py`)
- `dissect/archive/tibx/lsm.py`, `dissect/archive/tibx/maps.py` — LSM mem-tree (C0)
  reading, merged into the extent and segment-index loaders
- `dissect/archive/tibx/segment.py` — the `comp=0x0001` (LZ4 / stored) segment variant
- `tests/_synth.py` — the synthetic archive fixtures

## License text

Both projects above are distributed under the MIT License:

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
