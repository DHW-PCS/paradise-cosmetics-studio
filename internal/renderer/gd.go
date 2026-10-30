package renderer

// This file contains a small, self-contained reimplementation of the parts of
// libgd that the frozen Blessing texture renderer relies on:
//
//   - the 7-bit-alpha truecolor pixel format (alpha 0 = opaque, 127 = transparent)
//   - gdAlphaBlend (gd.c, libgd 2.3.x)
//   - gdImageCopy's truecolor path
//   - gdImageCopyResampled's truecolor path (area-weighted, float32 arithmetic)
//   - gdImageFilledPolygon / gdImageLine's horizontal fill
//
// The arithmetic deliberately mirrors libgd so that the Go renderer produces
// the same pixels as the PHP oracle, including its rounding behaviour.

import (
	"image"
	"image/color"
	"math"
)

const (
	gdAlphaMax         = 127
	gdAlphaOpaque      = 0
	gdAlphaTransparent = 127
)

// gdColor mirrors libgd's integer color layout: AAAAAAAARRRRRRRRGGGGGGGGBBBBBBBB
// where the alpha channel uses GD's 7-bit scale (0 opaque .. 127 transparent).
type gdColor int32

func gdRGBA(r, g, b, a int) gdColor {
	return gdColor((a << 24) | (r << 16) | (g << 8) | b)
}

func gdRed(c gdColor) int   { return int(c>>16) & 0xFF }
func gdGreen(c gdColor) int { return int(c>>8) & 0xFF }
func gdBlue(c gdColor) int  { return int(c) & 0xFF }
func gdAlpha(c gdColor) int { return (int(c) >> 24) & 0x7F }

// alphaFrom8 converts an 8-bit PNG alpha value to GD's 7-bit alpha scale the
// way libgd's PNG loader does (a = 127 - (a8 >> 1)).
func alphaFrom8(a uint8) int { return gdAlphaMax - (int(a) >> 1) }

// alphaTo8 converts GD's 7-bit alpha back to the 8-bit value libgd writes into
// PNG files (255 - ((a << 1) + (a >> 6))).
func alphaTo8(a int) uint8 {
	return uint8(255 - ((a << 1) + (a >> 6)))
}

// gdImage is a truecolor GD-style canvas.
type gdImage struct {
	w, h int
	px   []gdColor
}

// newGDImage returns a canvas filled like ImageUtil::createEmptyCanvas: fully
// transparent white (RGBA 255,255,255,127).
func newGDImage(w, h int) *gdImage {
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	im := &gdImage{w: w, h: h, px: make([]gdColor, w*h)}
	im.fillRaw(gdRGBA(255, 255, 255, gdAlphaTransparent))
	return im
}

func (im *gdImage) fillRaw(c gdColor) {
	for i := range im.px {
		im.px[i] = c
	}
}

// pixel returns the pixel like libgd's gdImageGetPixel: out-of-bounds reads
// yield 0 (opaque black).
func (im *gdImage) pixel(x, y int) gdColor {
	if x < 0 || y < 0 || x >= im.w || y >= im.h {
		return 0
	}
	return im.px[y*im.w+x]
}

// setPixel mirrors gdImageSetPixel for truecolor images with normal alpha
// blending enabled.
func (im *gdImage) setPixel(x, y int, c gdColor) {
	if x < 0 || y < 0 || x >= im.w || y >= im.h {
		return
	}
	im.px[y*im.w+x] = gdAlphaBlend(im.px[y*im.w+x], c)
}

// gdAlphaBlend is a direct port of libgd's gdAlphaBlend.
func gdAlphaBlend(dst, src gdColor) gdColor {
	srcAlpha := gdAlpha(src)
	if srcAlpha == gdAlphaOpaque {
		return src
	}
	dstAlpha := gdAlpha(dst)
	if srcAlpha == gdAlphaTransparent {
		return dst
	}
	if dstAlpha == gdAlphaTransparent {
		return src
	}
	srcWeight := gdAlphaTransparent - srcAlpha
	dstWeight := (gdAlphaTransparent - dstAlpha) * srcAlpha / gdAlphaMax
	totWeight := srcWeight + dstWeight
	alpha := srcAlpha * dstAlpha / gdAlphaMax
	red := (gdRed(src)*srcWeight + gdRed(dst)*dstWeight) / totWeight
	green := (gdGreen(src)*srcWeight + gdGreen(dst)*dstWeight) / totWeight
	blue := (gdBlue(src)*srcWeight + gdBlue(dst)*dstWeight) / totWeight
	return gdRGBA(red, green, blue, alpha)
}

// fillRect is gdImageFilledRectangle with an already allocated color: both
// endpoints are inclusive and the rectangle is clipped to the canvas.
func (im *gdImage) fillRect(x1, y1, x2, y2 int, c gdColor) {
	if x1 > x2 {
		x1, x2 = x2, x1
	}
	if y1 > y2 {
		y1, y2 = y2, y1
	}
	for y := y1; y <= y2; y++ {
		for x := x1; x <= x2; x++ {
			im.setPixel(x, y, c)
		}
	}
}

// blendCopy mirrors gdImageCopy when the destination is truecolor.
func blendCopy(dst, src *gdImage, dstX, dstY, srcX, srcY, w, h int) {
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := src.pixel(srcX+x, srcY+y)
			dst.setPixel(dstX+x, dstY+y, c)
		}
	}
}

func floor32(v float32) float32 {
	return float32(math.Floor(float64(v)))
}

// resample is a port of the bundled PHP 8.1 gdImageCopyResampled truecolor
// path (ext/gd/libgd/gd.c). PHP's bundled GD uses double precision here, unlike
// upstream libgd 2.3.x which uses float; the Go port follows the PHP behaviour
// because that is what the oracle runs.
func resample(dst, src *gdImage, dstX, dstY, srcX, srcY, dstW, dstH, srcW, srcH int) {
	if dstW <= 0 || dstH <= 0 || srcW <= 0 || srcH <= 0 {
		return
	}
	for y := dstY; y < dstY+dstH; y++ {
		sy1 := float64(y-dstY) * float64(srcH) / float64(dstH)
		sy2 := float64(y+1-dstY) * float64(srcH) / float64(dstH)
		for x := dstX; x < dstX+dstW; x++ {
			sx1 := float64(x-dstX) * float64(srcW) / float64(dstW)
			sx2 := float64(x+1-dstX) * float64(srcW) / float64(dstW)
			var spixels, red, green, blue, alpha float64
			var alphaSum, contribSum float64
			sy := sy1
			for {
				var yportion float64
				if math.Floor(sy) == math.Floor(sy1) {
					yportion = 1 - (sy - math.Floor(sy))
					if yportion > sy2-sy1 {
						yportion = sy2 - sy1
					}
					sy = math.Floor(sy)
				} else if sy == math.Floor(sy2) {
					yportion = sy2 - math.Floor(sy2)
				} else {
					yportion = 1
				}
				sx := sx1
				for {
					var xportion float64
					if math.Floor(sx) == math.Floor(sx1) {
						xportion = 1 - (sx - math.Floor(sx))
						if xportion > sx2-sx1 {
							xportion = sx2 - sx1
						}
						sx = math.Floor(sx)
					} else if sx == math.Floor(sx2) {
						xportion = sx2 - math.Floor(sx2)
					} else {
						xportion = 1
					}
					pcontribution := xportion * yportion
					p := src.pixel(int(sx)+srcX, int(sy)+srcY)
					alphaFactor := float64(gdAlphaMax-gdAlpha(p)) * pcontribution
					red += float64(gdRed(p)) * alphaFactor
					green += float64(gdGreen(p)) * alphaFactor
					blue += float64(gdBlue(p)) * alphaFactor
					alpha += float64(gdAlpha(p)) * pcontribution
					alphaSum += alphaFactor
					contribSum += pcontribution
					spixels += xportion * yportion
					sx += 1.0
					if !(sx < sx2) {
						break
					}
				}
				sy += 1.0
				if !(sy < sy2) {
					break
				}
			}

			if spixels != 0.0 {
				red /= spixels
				green /= spixels
				blue /= spixels
				alpha /= spixels
			}
			if alphaSum != 0.0 {
				if contribSum != 0.0 {
					alphaSum /= contribSum
				}
				red /= alphaSum
				green /= alphaSum
				blue /= alphaSum
			}
			// Round up closest next channel value and clamp to max channel value.
			if red >= 255.5 {
				red = 255
			} else {
				red = red + 0.5
			}
			if green >= 255.5 {
				green = 255
			} else {
				green = green + 0.5
			}
			if blue >= 255.5 {
				blue = 255
			} else {
				blue = blue + 0.5
			}
			if alpha >= gdAlphaMax+0.5 {
				alpha = gdAlphaMax
			} else {
				alpha = alpha + 0.5
			}
			dst.setPixel(x, y, gdRGBA(int(red), int(green), int(blue), int(alpha)))
		}
	}
}

// fromImage converts a decoded Go image into a GD-style truecolor canvas.
//
// The alpha channel is mapped onto GD's 7-bit scale exactly as libgd's PNG
// loader does. Paletted images are converted the way gdImageCopy converts a
// palette source: fully transparent palette entries become transparent white
// (255,255,255) because libgd skips the transparent index and leaves the
// transparent-white canvas fill in place.
func fromImage(src image.Image) *gdImage {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	im := &gdImage{w: w, h: h, px: make([]gdColor, w*h)}

	if p, ok := src.(*image.Paletted); ok {
		transparentWhite := gdRGBA(255, 255, 255, gdAlphaTransparent)
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				idx := p.ColorIndexAt(b.Min.X+x, b.Min.Y+y)
				var nc color.NRGBA
				if int(idx) < len(p.Palette) {
					nc = color.NRGBAModel.Convert(p.Palette[idx]).(color.NRGBA)
				}
				if nc.A == 0 {
					im.px[y*w+x] = transparentWhite
					continue
				}
				im.px[y*w+x] = gdRGBA(int(nc.R), int(nc.G), int(nc.B), alphaFrom8(nc.A))
			}
		}
		return im
	}

	if n, ok := src.(*image.NRGBA); ok {
		for y := 0; y < h; y++ {
			row := n.Pix[y*n.Stride : y*n.Stride+w*4]
			for x := 0; x < w; x++ {
				a := row[x*4+3]
				im.px[y*w+x] = gdRGBA(int(row[x*4]), int(row[x*4+1]), int(row[x*4+2]), alphaFrom8(a))
			}
		}
		return im
	}

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			nc := color.NRGBAModel.Convert(src.At(b.Min.X+x, b.Min.Y+y)).(color.NRGBA)
			im.px[y*w+x] = gdRGBA(int(nc.R), int(nc.G), int(nc.B), alphaFrom8(nc.A))
		}
	}
	return im
}

// toImage exports the canvas as an NRGBA image, applying the same 7-bit to
// 8-bit alpha expansion libgd uses when writing PNG files.
func (im *gdImage) toImage() image.Image {
	out := image.NewNRGBA(image.Rect(0, 0, im.w, im.h))
	for i, c := range im.px {
		out.Pix[i*4] = uint8(gdRed(c))
		out.Pix[i*4+1] = uint8(gdGreen(c))
		out.Pix[i*4+2] = uint8(gdBlue(c))
		out.Pix[i*4+3] = alphaTo8(gdAlpha(c))
	}
	return out
}
