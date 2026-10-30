package renderer

import (
	"image"
	"image/color"
)

// IsAlex reports whether a skin texture should use the Alex (slim) arm model.
//
// This is a port of Blessing\Renderer\TextureUtil::isAlex: the texture must be
// square, and every pixel of the 2x64-wide strip at the start of the left arm
// area (x in [46,48)*ratio, y in [52,64)*ratio) must have black RGB channels.
// As in the original, the alpha channel is ignored.
//
// The frozen PHP helper throws for square textures whose 46/64 ratio is not an
// integer (for example 100x100). This port samples such textures instead and
// always returns a boolean; uploads are expected to use the standard 64x32,
// 64x64 or 128x128 dimensions anyway.
func IsAlex(src image.Image) bool {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w != h {
		return false
	}

	ratio := float64(w) / 64
	for x := 46 * ratio; x < 48*ratio; x += 1 {
		for y := 52 * ratio; y < 64*ratio; y += 1 {
			if !isBlackPixel(src, b.Min.X+int(x), b.Min.Y+int(y)) {
				return false
			}
		}
	}
	return true
}

func isBlackPixel(src image.Image, x, y int) bool {
	b := src.Bounds()
	if x < b.Min.X || y < b.Min.Y || x >= b.Max.X || y >= b.Max.Y {
		return false
	}
	c := color.NRGBAModel.Convert(src.At(x, y)).(color.NRGBA)
	return c.R == 0 && c.G == 0 && c.B == 0
}
