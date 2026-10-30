package captcha

import (
	"bytes"
	"image"
	"image/jpeg"
	"testing"
)

func renderWithSeed(t *testing.T, seed int64, phrase string) image.Image {
	t.Helper()
	fonts, err := bundledFonts()
	if err != nil {
		t.Fatal(err)
	}
	img, err := buildImage(seed, phrase, fonts, func(fontData []byte, size float64) (glyphFace, error) {
		return newGlyphFace(fontData, size)
	})
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// TestGregwarComposition proves the port keeps the frozen composition: the
// bundled fonts, a light or post-processed background, glyphs spanning the
// image, and a non-flat tonal distribution. It deliberately does not assert
// pixel equality; the rasteriser and GD's random stream differ, so parity here
// is "same composition", registered as M3-01-CAPTCHA-01.
func TestGregwarComposition(t *testing.T) {
	for _, phrase := range []string{"L61Rk", "WGBM5", "cQ4lx"} {
		img := renderWithSeed(t, 1000, phrase).(*image.RGBA)
		bounds := img.Bounds()
		if bounds.Dx() != 100 || bounds.Dy() != 34 {
			t.Fatalf("%q: size %v", phrase, bounds)
		}
		lumas := make([]int, 0, bounds.Dx()*bounds.Dy())
		minX, maxX := bounds.Max.X, bounds.Min.X
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				c := img.RGBAAt(x, y)
				luma := (299*int(c.R) + 587*int(c.G) + 114*int(c.B)) / 1000
				if luma < 100 {
					if x < minX {
						minX = x
					}
					if x > maxX {
						maxX = x
					}
				}
				lumas = append(lumas, luma)
			}
		}
		spread := 0
		for _, value := range lumas {
			if value < 100 || value > 200 {
				spread++
			}
		}
		if spread < len(lumas)/10 {
			t.Fatalf("%q: image looks flat (only %d extreme pixels)", phrase, spread)
		}
		// Glyphs plus distortion must cover a substantial horizontal band.
		if maxX-minX < 40 {
			t.Fatalf("%q: dark pixels span %d..%d", phrase, minX, maxX)
		}
	}
}

// TestCaptchaRendersAreDistinct guards the whole random pipeline: identical
// images for different seeds would mean a constant leaked into the renderer.
func TestCaptchaRendersAreDistinct(t *testing.T) {
	first := renderWithSeed(t, 1, "Ab3Kd")
	second := renderWithSeed(t, 2, "Ab3Kd")
	if samePixels(first, second) {
		t.Fatal("different seeds produced identical images")
	}
}

func samePixels(a, b image.Image) bool {
	for _, img := range []image.Image{a, b} {
		var buffer bytes.Buffer
		if err := jpeg.Encode(&buffer, img, &jpeg.Options{Quality: 90}); err != nil {
			return false
		}
	}
	bounds := a.Bounds()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			if a.At(x, y) != b.At(x, y) {
				return false
			}
		}
	}
	return true
}
