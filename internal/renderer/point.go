package renderer

// Bounds mirrors the min/max accumulators passed by reference through the
// frozen renderer's projection methods.
type bounds struct {
	minX, maxX float64
	minY, maxY float64
}

func (b *bounds) include(x, y float64) {
	if x < b.minX {
		b.minX = x
	}
	if x > b.maxX {
		b.maxX = x
	}
	if y < b.minY {
		b.minY = y
	}
	if y > b.maxY {
		b.maxY = y
	}
}

// point is a port of Blessing\Renderer\Point.
type point struct {
	ox, oy, oz float64

	dx, dy, dz float64

	projected    bool
	preProjected bool
}

func newPoint(x, y, z float64) *point {
	return &point{ox: x, oy: y, oz: z}
}

func (p *point) project(cosAlpha, sinAlpha, cosOmega, sinOmega float64, b *bounds) {
	x, y, z := p.ox, p.oy, p.oz
	p.dx = x*cosOmega + z*sinOmega
	p.dy = x*sinAlpha*sinOmega + y*cosAlpha - z*sinAlpha*cosOmega
	p.dz = -x*cosAlpha*sinOmega + y*sinAlpha + z*cosAlpha*cosOmega
	p.projected = true
	b.include(p.dx, p.dy)
}

func (p *point) preProject(dx, dy, dz, cosAlpha, sinAlpha, cosOmega, sinOmega float64) {
	if p.preProjected {
		return
	}
	x := p.ox - dx
	y := p.oy - dy
	z := p.oz - dz
	p.ox = x*cosOmega + z*sinOmega + dx
	p.oy = x*sinAlpha*sinOmega + y*cosAlpha - z*sinAlpha*cosOmega + dy
	p.oz = -x*cosAlpha*sinOmega + y*sinAlpha + z*cosAlpha*cosOmega + dz
	p.preProjected = true
}

// depth mirrors Point::getDepth. Every caller in the frozen renderer has
// already projected the point, so the lazy projection branch is not needed.
func (p *point) depth() float64 {
	return p.dz
}
