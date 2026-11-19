# Third-party notices

## `static/assets/pq.js`

A verbatim vendor bundle of the post-quantum primitives the share pages
use, produced once with esbuild (no build step at deploy time) and committed
as a static asset. Exposes one global, `SFS_PQ`.

- `@noble/post-quantum` 0.7.1 — ML-KEM-1024 (FIPS 203).
  https://github.com/paulmillr/noble-post-quantum
- `@noble/hashes` 2.4.0 — HKDF-SHA256, SHA-256.
  https://github.com/paulmillr/noble-hashes

Both are MIT © Paul Miller. The full license texts are reproduced below.

## MIT License (both packages)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
