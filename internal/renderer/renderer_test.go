package renderer

import (
	"image"
	"image/color"
	"strconv"
	"testing"
)

// syntheticSkin builds a deterministic test texture without touching the
// filesystem. For square textures the lower half uses overlay-like alpha values
// (opaque, half transparent and fully transparent), mirroring the interesting
// parts of a modern skin.
func syntheticSkin(w, h int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r := uint8((x*37 + y*17 + 11) % 256)
			g := uint8((x*17 + y*37 + 91) % 256)
			b := uint8((x*7 + y*3 + 201) % 256)
			a := uint8(255)
			if w == h && y >= h/2 {
				switch (x + y) % 5 {
				case 0:
					a = 0
				case 1:
					a = 128
				}
			}
			img.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: a})
		}
	}
	return img
}

func transparentSkin(w, h int) *image.NRGBA {
	return image.NewNRGBA(image.Rect(0, 0, w, h))
}

func dims(img image.Image) (int, int) {
	b := img.Bounds()
	return b.Dx(), b.Dy()
}

func assertDims(t *testing.T, name string, img image.Image, wantW, wantH int) {
	t.Helper()
	if img == nil {
		t.Fatalf("%s: nil image", name)
	}
	w, h := dims(img)
	if w != wantW || h != wantH {
		t.Errorf("%s: got %dx%d, want %dx%d", name, w, h, wantW, wantH)
	}
}

func nrgbaAt(t *testing.T, img image.Image, x, y int) color.NRGBA {
	t.Helper()
	b := img.Bounds()
	if x < b.Min.X || y < b.Min.Y || x >= b.Max.X || y >= b.Max.Y {
		t.Fatalf("pixel (%d,%d) outside %v", x, y, b)
	}
	return color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
}

func countDiff(a, b image.Image) int {
	ab, bb := a.Bounds(), b.Bounds()
	if ab.Dx() != bb.Dx() || ab.Dy() != bb.Dy() {
		return -1
	}
	diff := 0
	for y := 0; y < ab.Dy(); y++ {
		for x := 0; x < ab.Dx(); x++ {
			ca := color.NRGBAModel.Convert(a.At(ab.Min.X+x, ab.Min.Y+y)).(color.NRGBA)
			cb := color.NRGBAModel.Convert(b.At(bb.Min.X+x, bb.Min.Y+y)).(color.NRGBA)
			if ca != cb {
				diff++
			}
		}
	}
	return diff
}

// TestOutputDimensions pins the sizes that the frozen PHP renderer produces for
// the original site parameters (preview ratio 12, cape height 200, avatar
// ratio 25). These numbers were captured from the PHP oracle.
func TestOutputDimensions(t *testing.T) {
	skin64 := syntheticSkin(64, 64)
	skin64x32 := syntheticSkin(64, 32)
	hd128 := syntheticSkin(128, 128)

	assertDims(t, "Skin 64x64", Skin(skin64, 12, false), 430, 437)
	assertDims(t, "Skin 64x32", Skin(skin64x32, 12, false), 430, 437)
	assertDims(t, "Skin 128x128", Skin(hd128, 12, false), 768, 845)

	assertDims(t, "Avatar2D 64x64", Avatar2D(skin64, 25), 225, 225)
	assertDims(t, "Avatar2D 64x32", Avatar2D(skin64x32, 25), 225, 225)
	assertDims(t, "Avatar2D 128x128", Avatar2D(hd128, 25), 450, 450)

	assertDims(t, "Avatar3D 64x64", Avatar3D(skin64, 25), 318, 338)
	assertDims(t, "Avatar3D 64x32", Avatar3D(skin64x32, 25), 318, 338)
	assertDims(t, "Avatar3D 128x128", Avatar3D(hd128, 25), 636, 677)

	assertDims(t, "Cape 200", Cape(skin64, 200), 205, 240)
	assertDims(t, "Cape 40", Cape(skin64, 40), 105, 80)
}

// TestSlimArmsDiffer ensures the Alex 3-pixel arm switch actually changes the
// rendered geometry.
func TestSlimArmsDiffer(t *testing.T) {
	skin := syntheticSkin(64, 64)
	classic := Skin(skin, 12, false)
	slim := Skin(skin, 12, true)

	if w1, h1 := dims(classic); w1 != 430 || h1 != 437 {
		t.Fatalf("classic preview has unexpected size %dx%d", w1, h1)
	}
	if w1, h1 := dims(slim); w1 != 430 || h1 != 437 {
		t.Fatalf("slim preview has unexpected size %dx%d", w1, h1)
	}
	if diff := countDiff(classic, slim); diff <= 0 {
		t.Fatalf("slim and classic previews are identical (%d differing pixels)", diff)
	}
}

// TestOutputAlpha checks that renders on a transparent canvas keep transparent
// background pixels and produce antialiased (partially transparent) edges.
func TestOutputAlpha(t *testing.T) {
	skin := syntheticSkin(64, 64)

	// The flat 2D avatar is the head's front face scaled to the full canvas, so
	// it is completely opaque; the other renders sit on a transparent canvas.
	if img := Avatar2D(skin, 25); img != nil {
		w, h := dims(img)
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				if a := nrgbaAt(t, img, x, y).A; a != 255 {
					t.Fatalf("avatar2d: pixel (%d,%d) alpha = %d, want fully opaque", x, y, a)
				}
			}
		}
	}

	for _, tc := range []struct {
		name    string
		img     image.Image
		wantBGT bool // transparent background corner expected
	}{
		{"preview", Skin(skin, 12, false), true},
		{"avatar3d", Avatar3D(skin, 25), true},
		{"cape", Cape(skin, 200), true},
	} {
		if _, ok := tc.img.(*image.NRGBA); !ok {
			t.Fatalf("%s: expected *image.NRGBA, got %T", tc.name, tc.img)
		}
		if tc.wantBGT {
			if corner := nrgbaAt(t, tc.img, 0, 0); corner.A != 0 {
				t.Errorf("%s: background corner alpha = %d, want 0 (transparent)", tc.name, corner.A)
			}
		}
		w, h := dims(tc.img)
		var hasOpaque, hasPartial bool
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				a := nrgbaAt(t, tc.img, x, y).A
				if a == 255 {
					hasOpaque = true
				} else if a > 0 && a < 255 {
					hasPartial = true
				}
			}
		}
		if !hasOpaque {
			t.Errorf("%s: expected at least one fully opaque pixel", tc.name)
		}
		if !hasPartial {
			t.Errorf("%s: expected antialiased partially transparent pixels", tc.name)
		}
	}
}

// TestTransparentSourceRendersBody documents the frozen renderer's behaviour for
// a texture whose base area is fully transparent: the base UV rectangles are
// pre-filled with opaque black, so the output contains a black body on a
// transparent background rather than being fully empty.
func TestTransparentSourceRendersBody(t *testing.T) {
	img := Skin(transparentSkin(64, 64), 12, false)
	assertDims(t, "transparent preview", img, 430, 437)

	if corner := nrgbaAt(t, img, 0, 0); corner.A != 0 {
		t.Errorf("transparent-source preview corner alpha = %d, want 0", corner.A)
	}

	opaque, black := 0, 0
	w, h := dims(img)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := nrgbaAt(t, img, x, y)
			if c.A == 255 {
				opaque++
				if c.R == 0 && c.G == 0 && c.B == 0 {
					black++
				}
			}
		}
	}
	if opaque == 0 {
		t.Fatal("transparent-source preview has no opaque pixels; expected the black pre-fill body")
	}
	if black == 0 {
		t.Fatal("transparent-source preview has no black pixels; expected the black pre-fill body")
	}
}

// TestOddSizesDoNotPanic covers degenerate and very small/large textures,
// including the internal 256-wide downscale path. It does not assert fidelity,
// only that rendering terminates with a usable image.
func TestOddSizesDoNotPanic(t *testing.T) {
	sizes := [][2]int{
		{1, 1}, {2, 3}, {8, 8}, {32, 32}, {64, 32}, {64, 64}, {128, 128},
		{256, 256}, {300, 200}, {512, 512},
	}
	for _, size := range sizes {
		w, h := size[0], size[1]
		src := syntheticSkin(w, h)
		name := func(kind string) string { return kind + " " + strconv.Itoa(w) + "x" + strconv.Itoa(h) }

		for _, tc := range []struct {
			kind string
			out  image.Image
		}{
			{"skin", Skin(src, 3, false)},
			{"skin-slim", Skin(src, 3, true)},
			{"cape", Cape(src, 20)},
			{"avatar2d", Avatar2D(src, 3)},
			{"avatar3d", Avatar3D(src, 3)},
		} {
			if tc.out == nil {
				t.Fatalf("%s: nil image", name(tc.kind))
			}
			ow, oh := dims(tc.out)
			if ow <= 0 || oh <= 0 {
				t.Fatalf("%s: invalid size %dx%d", name(tc.kind), ow, oh)
			}
		}
	}
}

// TestDeterministic ensures rendering is stateless: the same input must produce
// byte-identical output on repeated calls.
func TestDeterministic(t *testing.T) {
	skin := syntheticSkin(64, 64)
	for i := 0; i < 2; i++ {
		first := Skin(skin, 12, true)
		second := Skin(skin, 12, true)
		if diff := countDiff(first, second); diff != 0 {
			t.Fatalf("iteration %d: repeated Skin calls differ in %d pixels", i, diff)
		}
	}
}

// TestRatioScalesOutput checks that ratio is used as an internal scale, not a
// size clamp.
func TestRatioScalesOutput(t *testing.T) {
	skin := syntheticSkin(64, 64)
	small := Skin(skin, 3, false)
	large := Skin(skin, 12, false)
	smallW, smallH := dims(small)
	largeW, largeH := dims(large)
	if smallW >= largeW || smallH >= largeH {
		t.Fatalf("ratio 3 (%dx%d) should be smaller than ratio 12 (%dx%d)", smallW, smallH, largeW, largeH)
	}
}

// TestIsAlex covers the slim-model detection heuristic.
func TestIsAlex(t *testing.T) {
	white := func(w, h int) *image.NRGBA {
		img := image.NewNRGBA(image.Rect(0, 0, w, h))
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				img.SetNRGBA(x, y, color.NRGBA{R: 255, G: 255, B: 255, A: 255})
			}
		}
		return img
	}

	// Right arm strip for a 64x64 skin: x in [46,48), y in [52,64).
	alex := white(64, 64)
	for y := 52; y < 64; y++ {
		for x := 46; x < 48; x++ {
			alex.SetNRGBA(x, y, color.NRGBA{})
		}
	}
	if !IsAlex(alex) {
		t.Error("expected black-arm-strip 64x64 texture to be detected as Alex")
	}

	alex.SetNRGBA(46, 52, color.NRGBA{R: 1, G: 0, B: 0, A: 255})
	if IsAlex(alex) {
		t.Error("expected detection to fail after a non-black texel")
	}

	// Non-square textures are never Alex, regardless of the strip.
	wide := white(64, 32)
	for y := 20; y < 32; y++ {
		for x := 46; x < 48; x++ {
			wide.SetNRGBA(x, y, color.NRGBA{})
		}
	}
	if IsAlex(wide) {
		t.Error("expected 64x32 texture to be reported as classic")
	}

	// HD textures scale the strip by width/64.
	hd := white(128, 128)
	for y := 104; y < 128; y++ {
		for x := 92; x < 96; x++ {
			hd.SetNRGBA(x, y, color.NRGBA{})
		}
	}
	if !IsAlex(hd) {
		t.Error("expected black-arm-strip 128x128 texture to be detected as Alex")
	}

	// Transparent-but-black texels count as black, matching the frozen helper.
	transparent := white(64, 64)
	for y := 52; y < 64; y++ {
		for x := 46; x < 48; x++ {
			transparent.SetNRGBA(x, y, color.NRGBA{R: 0, G: 0, B: 0, A: 0})
		}
	}
	if !IsAlex(transparent) {
		t.Error("expected transparent black strip to be detected as Alex (alpha is ignored upstream)")
	}
}

// Benchmarks give M3-06 rough per-request costs for the site's render
// parameters (preview ratio 12).
func BenchmarkSkinPreview64(b *testing.B) {
	src := syntheticSkin(64, 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Skin(src, 12, false)
	}
}

func BenchmarkSkinPreview128(b *testing.B) {
	src := syntheticSkin(128, 128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Skin(src, 12, false)
	}
}

func BenchmarkSkinPreview512(b *testing.B) {
	src := syntheticSkin(512, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Skin(src, 12, false)
	}
}

func BenchmarkAvatar3D64(b *testing.B) {
	src := syntheticSkin(64, 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Avatar3D(src, 25)
	}
}

// TestDefensiveParameters pins the defensive handling of non-positive ratio and
// height values (the site always passes 12/25/200; the frozen PHP code errors on
// these inputs instead).
func TestDefensiveParameters(t *testing.T) {
	skin := syntheticSkin(64, 64)
	for _, img := range []image.Image{
		Skin(skin, 0, false),
		Skin(skin, -3, true),
		Cape(skin, 0),
		Cape(skin, -10),
		Avatar2D(skin, 0),
		Avatar3D(skin, 0),
	} {
		if img == nil {
			t.Fatal("nil image for defensive parameter")
		}
		if w, h := dims(img); w < 1 || h < 1 {
			t.Fatalf("invalid size %dx%d for defensive parameter", w, h)
		}
	}
}

// TestTransparentSourceAllKinds ensures every entry point handles a fully
// transparent texture without panicking.
func TestTransparentSourceAllKinds(t *testing.T) {
	src := transparentSkin(64, 64)
	for _, img := range []image.Image{
		Skin(src, 12, false), Cape(src, 200), Avatar2D(src, 25), Avatar3D(src, 25),
	} {
		if img == nil {
			t.Fatal("nil image for transparent source")
		}
		if w, h := dims(img); w < 1 || h < 1 {
			t.Fatalf("invalid size %dx%d for transparent source", w, h)
		}
	}
}
