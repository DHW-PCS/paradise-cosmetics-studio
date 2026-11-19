# Third-party notices

## Blessing Skin Server and plugins

The frontend sources, locale files and bundled images under `web/frontend/resources`, the original dependency lockfile, the adapted Go templates, and the legacy fixture schema and Steve PNG come from [Blessing Skin Server 6.0.2](https://github.com/bs-community/blessing-skin-server). The fixture also includes table definitions from [Blessing Skin plugins](https://github.com/bs-community/blessing-skin-plugins).

These materials are copyright 2016-present The Blessing Skin Team and use the MIT License. See [web/frontend/LICENSE](web/frontend/LICENSE) for the complete original notice.

Go module versions and checksums are in [go.mod](go.mod) and [go.sum](go.sum). Frontend dependency versions are pinned in [web/frontend/yarn.lock](web/frontend/yarn.lock).

## PCRE2 and SLJIT

PCS statically links the bundled PCRE2 10.39 maintenance library and its SLJIT compiler using CGO. Copyright 1997 to 2021 University of Cambridge, 2010 to 2021 Zoltan Herczeg (PCRE2 JIT), and 2009 to 2021 Zoltan Herczeg (SLJIT).

The [BSD license](internal/pcre/LICENCE) includes the binary redistribution terms. `make build` copies it to `dist/licenses/PCRE2.txt`. See the [PCRE2 maintenance notes](internal/pcre/README.md) for the pinned revision and source archive.

## Minecraft texture renderer

[`internal/renderer`](internal/renderer) ports the `blessing/texture-renderer` PHP package from Blessing Skin Server 6.0.2. The PHP implementation is copyright 2020-present The Blessing Skin Team and uses the [MIT License](internal/renderer/LICENSE-MIT). Its underlying PHP Minecraft Skin Renderer algorithm is copyright 2012 Pierre Gros and uses the [BSD license](internal/renderer/LICENSE-BSD).

The Go port keeps the upstream UV mapping, projection, visible-face selection, draw order and GD-compatible rasterisation and antialiasing. It uses the Go standard library.

## CAPTCHA fonts

### gregwar/captcha

The renderer embeds six font files (`captcha0.ttf` through `captcha5.ttf`) from gregwar/captcha v1.1.9. The copies in `internal/captcha/fonts/` are unchanged from the Blessing Skin Server 6.0.2 vendor tree. Copyright 2012 to 2017 Grégoire Passault. See the [MIT notice](internal/captcha/fonts/GREGWRAR-LICENSE.txt).

### Go fonts

The renderer also uses the Go fonts from `golang.org/x/image` v0.47.0. Bigelow & Holmes created these fonts for the Go project. See [Go fonts](https://blog.golang.org/go-fonts).

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
