# Third-party material

The frontend sources, locale files and bundled images under `web/frontend/resources`, the original dependency lockfile, and the adapted Go templates originate from Blessing Skin Server 6.0.2, copyright 2016-present The Blessing Skin Team, under the MIT License. The complete original notice is preserved in [web/frontend/LICENSE](web/frontend/LICENSE).

The original project is [bs-community/blessing-skin-server](https://github.com/bs-community/blessing-skin-server). Go module dependencies and their pinned versions are recorded in `go.mod` and `go.sum`; frontend dependencies remain pinned by `web/frontend/yarn.lock`.

## Native PCRE2 (`internal/pcre`)

The bundled PCRE2 10.39 maintenance sources are fixed at upstream commit
`07eb542ff0b19bebc47221ced817362b652f8098`, including upstream backports. The
library and its SLJIT compiler are statically linked with CGO. Copyright
1997–2021 University of Cambridge, 2010–2021 Zoltan Herczeg (PCRE2 JIT), and
2009–2021 Zoltan Herczeg (SLJIT). The complete BSD license and binary
redistribution terms are preserved in [internal/pcre/LICENCE](internal/pcre/LICENCE).
`make build` copies this license into `dist/licenses/PCRE2.txt` for distribution.
Source provenance and build configuration are in [internal/pcre/README.md](internal/pcre/README.md).

## CAPTCHA fonts

The CAPTCHA renderer embeds the six `captcha0.ttf`–`captcha5.ttf` faces that ship
with gregwar/captcha v1.1.9, copied unmodified from the frozen 6.0.2 vendor tree
into `internal/captcha/fonts/`. They are distributed under the MIT License,
copyright 2012–2017 Grégoire Passault; the complete notice is preserved in
[internal/captcha/fonts/GREGWRAR-LICENSE.txt](internal/captcha/fonts/GREGWRAR-LICENSE.txt).

The renderer also uses the font stack from golang.org/x/image v0.47.0.

These fonts were created by the Bigelow & Holmes foundry specifically for the
Go project. See https://blog.golang.org/go-fonts for details.

They are licensed under the same open source license as the rest of the Go
project's software:

Copyright (c) 2016 Bigelow & Holmes Inc.. All rights reserved.

Distribution of this font is governed by the following license. If you do not
agree to this license, including the disclaimer, do not distribute or modify
this font.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.

	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.

	* Neither the name of Google Inc. nor the names of its contributors may be
	  used to endorse or promote products derived from this software without
	  specific prior written permission.

DISCLAIMER: THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Minecraft texture renderer (`internal/renderer`)

`internal/renderer` is a Go port of the `blessing/texture-renderer` PHP package
bundled with Blessing Skin Server 6.0.2.
The PHP implementation is MIT licensed, copyright 2020-present The Blessing Skin
Team; the Minecraft skin rendering algorithm it is based on (PHP Minecraft Skin
Renderer) is BSD licensed, copyright 2012, Pierre Gros. The complete license
texts are preserved in `internal/renderer/LICENSE-MIT` and
`internal/renderer/LICENSE-BSD`.

The Go port keeps the upstream UV mapping, projection, visible-face selection,
draw order and GD-compatible rasterisation/antialiasing. It uses only the Go
standard library (no CGO, no third-party packages).
