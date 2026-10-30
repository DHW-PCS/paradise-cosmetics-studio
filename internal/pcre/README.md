# Native PCRE2

This package compiles the PCRE2 10.39 8-bit library into the Go binary with
CGO. A target C compiler is required (`CGO_ENABLED=1`); there is no system
PCRE2 or PHP runtime dependency. Cross builds also need a target C toolchain.
Distribute [LICENCE](LICENCE) with the binary.

Upstream: [PCRE2 release/pcre2-10.39 maintenance branch](https://github.com/PCRE2Project/pcre2/tree/07eb542ff0b19bebc47221ced817362b652f8098),
fixed at commit `07eb542ff0b19bebc47221ced817362b652f8098`. This includes the
10.39 backports listed in the upstream [support lifecycle](https://github.com/PCRE2Project/pcre2/blob/main/SUPPORT-LIFECYCLE.md).
The [source archive](https://codeload.github.com/PCRE2Project/pcre2/tar.gz/07eb542ff0b19bebc47221ced817362b652f8098)
SHA-256 is `e49c202e0f17b3a1f01ec77e23cd69d200785adf1aec916d2016e6f3f791cce7`.
The library sources, headers and `sljit/` are unchanged from this commit. Following upstream
`NON-AUTOTOOLS-BUILD`, `config.h.generic`, `pcre2.h.generic` and
`pcre2_chartables.c.dist` become `config.h`, `pcre2.h` and
`pcre2_chartables.c`. The two included JIT C files live in `include/` so CGO
does not compile them as separate translation units.

`native.go` supplies build flags for Unicode, JIT and the 8-bit API. The default
C character tables match the frozen PHP `LC_CTYPE=C.UTF-8` byte classes;
the process locale is not changed. `/u` enables UTF and UCP, as PHP 8.1 does.
`adapter.c` sets the frozen match/depth limits and JIT stack sizes. PCRE2's
documented interpreter path handles patterns the JIT cannot compile.
The compile context enables PHP's lookaround `\K` compatibility option.

`testdata/php81.json` contains synthetic results from PHP 8.1.34 / PCRE2
10.39, with JIT enabled, match limit 1,000,000 and depth limit 100,000. It
covers the previous engine's failures, PHP delimiters/modifiers, Unicode,
binary subjects, execution limits, and all 256 bytes for four character
classes. Run `go test -race ./internal/pcre` after changing the adapter or
native library. Library upgrades need a fresh cross-implementation comparison;
using a different system release would change the qualified engine.
Check the upstream maintenance branch and support lifecycle for new backports
when preparing a release, and repeat qualification before updating this copy.
