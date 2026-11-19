# Native PCRE2

PCS uses PCRE2 for the legacy name rules to match the PHP 8.1 baseline. CGO builds the bundled 8-bit library into the Go binary. Build with `CGO_ENABLED=1` and a C compiler for the target, including for cross builds. The binary does not use a system PCRE2 or a PHP runtime. Distribute [LICENCE](LICENCE) with the binary. `make build` copies it to `dist/licenses/PCRE2.txt`.

## Bundled source

The library comes from the [PCRE2 10.39 maintenance branch](https://github.com/PCRE2Project/pcre2/tree/07eb542ff0b19bebc47221ced817362b652f8098) at commit `07eb542ff0b19bebc47221ced817362b652f8098`, including the backports at that revision. The [source archive](https://codeload.github.com/PCRE2Project/pcre2/tar.gz/07eb542ff0b19bebc47221ced817362b652f8098) has SHA-256 `e49c202e0f17b3a1f01ec77e23cd69d200785adf1aec916d2016e6f3f791cce7`.

The library sources, headers and `sljit/` are unchanged from that commit. Following upstream `NON-AUTOTOOLS-BUILD`, copy `config.h.generic`, `pcre2.h.generic` and `pcre2_chartables.c.dist` to `config.h`, `pcre2.h` and `pcre2_chartables.c`, respectively. The two JIT sources included by other C files live under `include/` so CGO does not compile them again as separate translation units.

## PHP compatibility

[`native.go`](native.go) selects Unicode, JIT and the 8-bit API. The default C character tables use the same byte classes as the PHP baseline with `LC_CTYPE=C.UTF-8`, without changing the process locale. The `/u` modifier enables UTF and UCP.

[`adapter.c`](adapter.c) sets the baseline match and depth limits and JIT stack sizes. The compile context allows PHP's use of `\K` in lookarounds. Patterns that JIT cannot compile use PCRE2's interpreter.

## Verify changes

After changing the adapter or bundled library, run this command from the repository root.

```sh
go test -race ./internal/pcre
```

[`testdata/php81.json`](testdata/php81.json) records results from synthetic cases run with PHP 8.1.34 and PCRE2 10.39. The reference run used JIT, a match limit of 1,000,000 and a depth limit of 100,000. The cases cover regressions from the previous engine, PHP delimiters and modifiers, Unicode, binary subjects, execution limits and all 256 byte values for four character classes.

When preparing a release, check upstream's [support lifecycle](https://github.com/PCRE2Project/pcre2/blob/main/SUPPORT-LIFECYCLE.md) and maintenance branch for backports. Before switching revisions, repeat the comparison against PHP. The existing results apply to the bundled revision.
