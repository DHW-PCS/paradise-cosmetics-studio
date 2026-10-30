package captcha

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"math"
	"math/rand"
)

// This file ports the visible parts of Gregwar\Captcha\CaptchaBuilder as it is
// configured by the frozen AuthController::captcha (build(100, 34) with the
// bundled fonts and default options). Rasterisation still differs from GD's
// FreeType backend, so parity is "same composition", not byte equality.

const (
	captchaWidth  = 100
	captchaHeight = 34
	// Defaults from CaptchaBuilder: maxAngle, maxOffset and JPEG quality.
	maxAngle  = 8
	maxOffset = 5
)

// drawTarget is the minimal 2D canvas the compositor needs. image.RGBA
// satisfies it; tests use it to capture intermediate stages.
type drawTarget interface {
	Bounds() image.Rectangle
	At(x, y int) color.Color
	Set(x, y int, c color.Color)
}

type builder struct {
	rand  *rand.Rand
	image *image.RGBA
	bg    color.RGBA
}

// renderer renders one challenge image and returns its answer.
type renderer struct {
	builder
	fonts [][]byte
	face  func(size float64) (glyphFace, error)
}

type glyphFace interface {
	drawChar(dst *image.RGBA, ch rune, size, angle float64, x, y float64, c color.RGBA)
	advance(ch rune, size float64) float64
	bounds(ch rune, size float64) (minY, maxY float64)
	close()
}

func newBuilder(seed int64, width, height int) *builder {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	b := &builder{rand: rand.New(rand.NewSource(seed)), image: img}
	return b
}

func (b *builder) spread(from, to int) int {
	if to <= from {
		return from
	}
	return from + b.rand.Intn(to-from+1)
}

func (b *builder) spreadFloat(from, to float64) float64 {
	if to <= from {
		return from
	}
	return from + b.rand.Float64()*(to-from)
}

// buildImage mirrors CaptchaBuilder::build up to (but excluding) encoding.
func buildImage(seed int64, phrase string, fonts [][]byte, faceFor func(font []byte, size float64) (glyphFace, error)) (*image.RGBA, error) {
	width, height := captchaWidth, captchaHeight
	b := newBuilder(seed, width, height)
	fontIndex := b.spread(0, len(fonts)-1)
	font := fonts[fontIndex]
	bg := color.RGBA{uint8(b.spread(200, 255)), uint8(b.spread(200, 255)), uint8(b.spread(200, 255)), 255}
	b.bg = bg
	fill(b.image, bg)

	// Lines behind the text.
	square := width * height
	behind := b.spread(square/3000, square/2000)
	for i := 0; i < behind; i++ {
		b.drawLine(width, height, nil)
	}

	size := float64(width)/float64(len(phrase)) - float64(b.spread(0, 3)) - 1
	face, err := faceFor(font, size)
	if err != nil {
		return nil, err
	}
	defer face.close()

	textColor := color.RGBA{uint8(b.spread(0, 150)), uint8(b.spread(0, 150)), uint8(b.spread(0, 150)), 255}
	// CaptchaBuilder centres the whole phrase using imagettfbbox at angle 0 and
	// then advances x by each glyph's width.
	textWidth := 0.0
	minY, maxY := 0.0, 0.0
	for _, ch := range phrase {
		textWidth += face.advance(ch, size)
		lo, hi := face.bounds(ch, size)
		minY = math.Min(minY, lo)
		maxY = math.Max(maxY, hi)
	}
	textHeight := maxY - minY
	x := (float64(width) - textWidth) / 2
	y := (float64(height)-textHeight)/2 + size
	for _, ch := range phrase {
		angle := float64(b.spread(-maxAngle, maxAngle))
		offset := float64(b.spread(-maxOffset, maxOffset))
		face.drawChar(b.image, ch, size, angle, x, y+offset, textColor)
		x += face.advance(ch, size)
	}

	// Lines in front of the text.
	front := b.spread(square/3000, square/2000)
	for i := 0; i < front; i++ {
		b.drawLine(width, height, &textColor)
	}

	distorted := b.distort(width, height)
	b.postEffect(distorted)
	return distorted, nil
}

func fill(img *image.RGBA, c color.RGBA) {
	bounds := img.Bounds()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			img.SetRGBA(x, y, c)
		}
	}
}

// drawLine mirrors CaptchaBuilder::drawLine.
func (b *builder) drawLine(width, height int, tcol *color.RGBA) {
	lineColor := color.RGBA{uint8(b.spread(100, 255)), uint8(b.spread(100, 255)), uint8(b.spread(100, 255)), 255}
	if tcol != nil {
		lineColor = *tcol
	}
	var xa, ya, xb, yb int
	if b.spread(0, 1) == 1 {
		xa, ya = b.spread(0, width/2), b.spread(0, height)
		xb, yb = b.spread(width/2, width), b.spread(0, height)
	} else {
		xa, ya = b.spread(0, width), b.spread(0, height/2)
		xb, yb = b.spread(0, width), b.spread(height/2, height)
	}
	thickness := b.spread(1, 3)
	drawLine(b.image, xa, ya, xb, yb, thickness, lineColor)
}

func drawLine(img *image.RGBA, x0, y0, x1, y1, thickness int, c color.RGBA) {
	dx := abs(x1 - x0)
	dy := abs(y1 - y0)
	steps := dx
	if dy > steps {
		steps = dy
	}
	if steps == 0 {
		img.SetRGBA(x0, y0, c)
		return
	}
	half := thickness / 2
	for i := 0; i <= steps; i++ {
		x := x0 + (x1-x0)*i/steps
		y := y0 + (y1-y0)*i/steps
		for oy := -half; oy <= half; oy++ {
			for ox := -half; ox <= half; ox++ {
				px, py := x+ox, y+oy
				if image.Pt(px, py).In(img.Bounds()) {
					img.SetRGBA(px, py, c)
				}
			}
		}
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// distort mirrors CaptchaBuilder::distort (radial sine plus vertical sine),
// using the same bilinear interpolation.
func (b *builder) distort(width, height int) *image.RGBA {
	src := b.image
	out := image.NewRGBA(image.Rect(0, 0, width, height))
	x0 := float64(b.spread(0, width))
	y0 := float64(b.spread(0, height))
	phase := float64(b.spread(0, 10))
	scale := 1.1 + float64(b.spread(0, 10000))/30000
	for x := 0; x < width; x++ {
		for y := 0; y < height; y++ {
			vx := float64(x) - x0
			vy := float64(y) - y0
			vn := math.Sqrt(vx*vx + vy*vy)
			var nx, ny float64
			if vn != 0 {
				vn2 := vn + 4*math.Sin(vn/30)
				nx = x0 + vx*vn2/vn
				ny = y0 + vy*vn2/vn
			} else {
				nx, ny = x0, y0
			}
			ny += scale * math.Sin(phase+nx*0.2)
			c := b.interpolate(src, nx, ny)
			out.SetRGBA(x, y, c)
		}
	}
	return out
}

func (b *builder) interpolate(src *image.RGBA, nx, ny float64) color.RGBA {
	fx, fy := nx-math.Floor(nx), ny-math.Floor(ny)
	ix, iy := int(math.Floor(nx)), int(math.Floor(ny))
	cx, cy := ix+1, iy+1
	v00 := sample(src, ix, iy, b.bg)
	v10 := sample(src, cx, iy, b.bg)
	v01 := sample(src, ix, cy, b.bg)
	v11 := sample(src, cx, cy, b.bg)
	lerp := func(a, c uint8) uint8 {
		top := float64(a)*(1-fx) + float64(c)*fx
		return uint8(math.Round(top))
	}
	top := color.RGBA{lerp(v00.R, v10.R), lerp(v00.G, v10.G), lerp(v00.B, v10.B), 255}
	bottom := color.RGBA{lerp(v01.R, v11.R), lerp(v01.G, v11.G), lerp(v01.B, v11.B), 255}
	lerpY := func(a, c uint8) uint8 {
		return uint8(math.Round(float64(a)*(1-fy) + float64(c)*fy))
	}
	return color.RGBA{lerpY(top.R, bottom.R), lerpY(top.G, bottom.G), lerpY(top.B, bottom.B), 255}
}

func sample(src *image.RGBA, x, y int, bg color.RGBA) color.RGBA {
	if !image.Pt(x, y).In(src.Bounds()) {
		return bg
	}
	c := src.RGBAAt(x, y)
	return color.RGBA{c.R, c.G, c.B, 255}
}

// postEffect mirrors CaptchaBuilder::postEffect (skipped when an explicit
// background or text colour was configured, which is not the frozen case).
func (b *builder) postEffect(img *image.RGBA) {
	if b.spread(0, 1) == 0 {
		negate(img)
	}
	if b.spread(0, 10) == 0 {
		edgeDetect(img)
	}
	adjustContrast(img, b.spread(-50, 10))
	if b.spread(0, 5) == 0 {
		colorize(img, b.spread(-80, 50), b.spread(-80, 50), b.spread(-80, 50))
	}
}

func negate(img *image.RGBA) {
	bounds := img.Bounds()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := img.RGBAAt(x, y)
			img.SetRGBA(x, y, color.RGBA{255 - c.R, 255 - c.G, 255 - c.B, c.A})
		}
	}
}

// edgeDetect approximates GD's IMG_FILTER_EDGEDETECT with a Sobel magnitude,
// which is what GD's convolution kernel implements.
func edgeDetect(img *image.RGBA) {
	bounds := img.Bounds()
	src := image.NewRGBA(bounds)
	copyPixels(src, img)
	for y := bounds.Min.Y + 1; y < bounds.Max.Y-1; y++ {
		for x := bounds.Min.X + 1; x < bounds.Max.X-1; x++ {
			gx := -int(luma(src, x-1, y-1)) - 2*int(luma(src, x-1, y)) - int(luma(src, x-1, y+1)) +
				int(luma(src, x+1, y-1)) + 2*int(luma(src, x+1, y)) + int(luma(src, x+1, y+1))
			gy := -int(luma(src, x-1, y-1)) - 2*int(luma(src, x, y-1)) - int(luma(src, x+1, y-1)) +
				int(luma(src, x-1, y+1)) + 2*int(luma(src, x, y+1)) + int(luma(src, x+1, y+1))
			magnitude := math.Sqrt(float64(gx*gx + gy*gy))
			if magnitude > 255 {
				magnitude = 255
			}
			v := uint8(magnitude)
			img.SetRGBA(x, y, color.RGBA{v, v, v, 255})
		}
	}
}

func luma(img *image.RGBA, x, y int) uint8 {
	c := img.RGBAAt(x, y)
	return uint8((299*int(c.R) + 587*int(c.G) + 114*int(c.B)) / 1000)
}

func copyPixels(dst, src *image.RGBA) {
	bounds := src.Bounds()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			dst.SetRGBA(x, y, src.RGBAAt(x, y))
		}
	}
}

// adjustContrast approximates GD's IMG_FILTER_CONTRAST lookup table. GD's exact
// integer table is not reproduced; the documented residual difference is the
// same order as the rasteriser difference.
func adjustContrast(img *image.RGBA, level int) {
	const maxLevel = 50
	if level > maxLevel {
		level = maxLevel
	}
	if level < -maxLevel {
		level = -maxLevel
	}
	// Negative levels spread values away from mid grey, positive levels flatten.
	// GD's table is not reproduced exactly; this keeps the same direction and a
	// comparable magnitude, and the residual is registered as a difference.
	factor := 1.0
	if level < 0 {
		factor = 1.0 - float64(level)/float64(maxLevel+1)
	} else if level > 0 {
		factor = 1.0 / (1.0 + float64(level)/float64(maxLevel+1))
	}
	applyFactor(img, factor)
}

func applyFactor(img *image.RGBA, factor float64) {
	bounds := img.Bounds()
	scale := func(v uint8) uint8 {
		out := (float64(v)-128)*factor + 128
		if out < 0 {
			out = 0
		}
		if out > 255 {
			out = 255
		}
		return uint8(math.Round(out))
	}
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := img.RGBAAt(x, y)
			img.SetRGBA(x, y, color.RGBA{scale(c.R), scale(c.G), scale(c.B), c.A})
		}
	}
}

// colorize mirrors IMG_FILTER_COLORIZE with the same arithmetic clamping.
func colorize(img *image.RGBA, r, g, b int) {
	bounds := img.Bounds()
	clamp := func(v int) uint8 {
		if v < 0 {
			return 0
		}
		if v > 255 {
			return 255
		}
		return uint8(v)
	}
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := img.RGBAAt(x, y)
			img.SetRGBA(x, y, color.RGBA{clamp(int(c.R) + r), clamp(int(c.G) + g), clamp(int(c.B) + b), c.A})
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func encodeJPEG(img image.Image) ([]byte, error) {
	var buffer bytes.Buffer
	if err := jpeg.Encode(&buffer, img, &jpeg.Options{Quality: 90}); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
