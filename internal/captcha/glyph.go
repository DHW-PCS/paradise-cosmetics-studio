package captcha

import (
	"image"
	"image/color"
	"math"

	"golang.org/x/image/font"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
)

// gdDPI is GD's default resolution for imagettftext.
const gdDPI = 96.0

// sfntGlyphFace draws one glyph with a rotation, mirroring imagettftext's
// baseline placement. The rasteriser differs from GD's FreeType backend, which
// is the registered residual difference for M3-01-CAPTCHA-01.
type sfntGlyphFace struct {
	raw       []byte
	face      font.Face
	size      float64
	ascent    float64
	descent   float64
	dotOffset float64
}

func newGlyphFace(fontData []byte, size float64) (*sfntGlyphFace, error) {
	parsed, err := opentype.Parse(fontData)
	if err != nil {
		return nil, err
	}
	// GD's imagettftext interprets the size in points at its default 96 DPI;
	// matching that DPI reproduces the frozen glyph height. HintingNone matches
	// GD's unhinted rendering.
	face, err := opentype.NewFace(parsed, &opentype.FaceOptions{Size: size, DPI: gdDPI, Hinting: font.HintingNone})
	if err != nil {
		return nil, err
	}
	metrics := face.Metrics()
	return &sfntGlyphFace{
		raw:     fontData,
		face:    face,
		size:    size,
		ascent:  float64(metrics.Ascent) / 64,
		descent: float64(metrics.Descent) / 64,
	}, nil
}

func (g *sfntGlyphFace) advance(ch rune, size float64) float64 {
	width, ok := g.face.GlyphAdvance(ch)
	if !ok {
		return 0
	}
	return float64(width) / 64
}

func (g *sfntGlyphFace) bounds(ch rune, size float64) (float64, float64) {
	bounds, _, _ := g.face.GlyphBounds(ch)
	return float64(bounds.Min.Y) / 64, float64(bounds.Max.Y) / 64
}

func (g *sfntGlyphFace) close() { g.face.Close() }

// drawChar renders one glyph into dst rotated around its baseline origin, like
// imagettftext. The glyph mask is rasterised at 1x and the destination pixel
// coverage is box-filtered from 4x4 sub-samples, so rotated strokes stay solid.
func (g *sfntGlyphFace) drawChar(dst *image.RGBA, ch rune, size, angle float64, x, y float64, c color.RGBA) {
	bounds, _, _ := g.face.GlyphBounds(ch)
	pad := int(math.Ceil(size)) + 4
	width := int(bounds.Max.X.Ceil()) + pad*2
	height := int(bounds.Max.Y.Ceil()-bounds.Min.Y.Ceil()) + pad*2
	if width <= 0 || height <= 0 {
		return
	}
	mask := image.NewAlpha(image.Rect(0, 0, width, height))
	baseline := float64(pad) + g.ascent
	dotY := int(math.Round(baseline))
	drawer := font.Drawer{
		Dst:  mask,
		Src:  image.NewUniform(color.Alpha{255}),
		Face: g.face,
		Dot:  fixed.P(pad-int(bounds.Min.X.Ceil()), dotY),
	}
	drawer.DrawString(string(ch))

	radians := angle * math.Pi / 180
	cosine, sine := math.Cos(radians), math.Sin(radians)
	originX, originY := float64(pad), float64(dotY)
	const samples = 4
	for py := 0; py < dst.Bounds().Dy(); py++ {
		for px := 0; px < dst.Bounds().Dx(); px++ {
			var total int
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					fx := float64(px) + (float64(sx)+0.5)/samples - x
					fy := float64(py) + (float64(sy)+0.5)/samples - y
					mx := originX + fx*cosine + fy*sine
					my := originY - fx*sine + fy*cosine
					total += int(mask.AlphaAt(int(math.Floor(mx)), int(math.Floor(my))).A)
				}
			}
			coverage := total / (samples * samples)
			if coverage == 0 {
				continue
			}
			composite(dst, px, py, c, uint8(coverage))
		}
	}
}

func composite(dst *image.RGBA, x, y int, c color.RGBA, alpha uint8) {
	existing := dst.RGBAAt(x, y)
	a := float64(alpha) / 255
	blend := func(src, dst uint8) uint8 {
		return uint8(math.Round(float64(src)*a + float64(dst)*(1-a)))
	}
	dst.SetRGBA(x, y, color.RGBA{blend(c.R, existing.R), blend(c.G, existing.G), blend(c.B, existing.B), 255})
}
