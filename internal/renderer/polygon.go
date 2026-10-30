package renderer

// polygon is a port of Blessing\Renderer\Polygon. Each polygon carries the
// texture color sampled from the source skin; the frozen renderer draws the
// sampled RGB fully opaque and skips texels whose GD alpha is exactly 127.
type polygon struct {
	dots  []*point
	color gdColor
}

// addPngPolygon mirrors Polygon::addPngPolygon: it projects the (already
// destination-projected) corners onto the canvas and fills the quad using GD's
// integer scanline rasterizer. Quads that collapse onto a screen-axis-aligned
// line are skipped, exactly like the frozen code.
func (p *polygon) addPngPolygon(im *gdImage, minX, minY, ratio float64) {
	if gdAlpha(p.color) == gdAlphaTransparent {
		return
	}
	if len(p.dots) == 0 {
		return
	}

	pts := make([]imagePoint, len(p.dots))
	firstX, firstY := p.dots[0].dx, p.dots[0].dy
	samePlanX, samePlanY := true, true
	for i, dot := range p.dots {
		if dot.dx != firstX {
			samePlanX = false
		}
		if dot.dy != firstY {
			samePlanY = false
		}
		pts[i] = imagePoint{
			x: int((dot.dx - minX) * ratio),
			y: int((dot.dy - minY) * ratio),
		}
	}
	if samePlanX || samePlanY {
		return
	}
	im.fillPolygon(pts, gdRGBA(gdRed(p.color), gdGreen(p.color), gdBlue(p.color), gdAlphaOpaque))
}

// imagePoint is an integer canvas coordinate (GD's gdPoint).
type imagePoint struct {
	x, y int
}

// fillPolygon is a port of libgd's gdImageFilledPolygon (non-antialiased).
func (im *gdImage) fillPolygon(p []imagePoint, color gdColor) {
	n := len(p)
	if n <= 0 {
		return
	}
	miny, maxy := p[0].y, p[0].y
	for _, pt := range p[1:] {
		if pt.y < miny {
			miny = pt.y
		}
		if pt.y > maxy {
			maxy = pt.y
		}
	}
	if n > 1 && miny == maxy {
		x1, x2 := p[0].x, p[0].x
		for _, pt := range p[1:] {
			if pt.x < x1 {
				x1 = pt.x
			} else if pt.x > x2 {
				x2 = pt.x
			}
		}
		im.hLine(miny, x1, x2, color)
		return
	}
	pmaxy := maxy
	if miny < 0 {
		miny = 0
	}
	if maxy > im.h-1 {
		maxy = im.h - 1
	}
	ints := make([]int, 0, n)
	for y := miny; y <= maxy; y++ {
		ints = ints[:0]
		for i := 0; i < n; i++ {
			ind1, ind2 := i-1, i
			if i == 0 {
				ind1, ind2 = n-1, 0
			}
			y1, y2 := p[ind1].y, p[ind2].y
			x1, x2 := p[ind1].x, p[ind2].x
			if y1 < y2 {
				// keep x1, y1, x2, y2 as-is
			} else if y1 > y2 {
				y1, y2 = y2, y1
				x1, x2 = x2, x1
			} else {
				continue
			}
			// Do the math in float32 like libgd, then round and truncate.
			if y >= y1 && y < y2 {
				v := float64(float32((y-y1)*(x2-x1))/float32(y2-y1)) + 0.5 + float64(x1)
				ints = append(ints, int(v))
			} else if y == pmaxy && y == y2 {
				ints = append(ints, x2)
			}
		}
		for i := 1; i < len(ints); i++ {
			index := ints[i]
			j := i
			for j > 0 && ints[j-1] > index {
				ints[j] = ints[j-1]
				j--
			}
			ints[j] = index
		}
		for i := 0; i+1 < len(ints); i += 2 {
			im.hLine(y, ints[i], ints[i+1], color)
		}
	}
}

// hLine is libgd's gdImageHLine with thickness 1.
func (im *gdImage) hLine(y, x1, x2 int, color gdColor) {
	if x2 < x1 {
		x1, x2 = x2, x1
	}
	if y < 0 || y >= im.h {
		return
	}
	if x1 < 0 {
		x1 = 0
	}
	if x2 > im.w-1 {
		x2 = im.w - 1
	}
	for x := x1; x <= x2; x++ {
		im.setPixel(x, y, color)
	}
}
