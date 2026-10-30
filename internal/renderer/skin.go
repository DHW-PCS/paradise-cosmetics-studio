package renderer

import (
	"image"
	"math"
)

// This file ports Blessing\Renderer\SkinRenderer (frozen 6.0.2) to Go. The
// control flow, UV mapping and floating point expressions intentionally match
// the PHP original, including its quirks (fixed-size layer copies for HD
// textures, mirrored legacy limb UVs, per-member rotations and GD's rasterizer).

const degToRad = math.Pi / 180

type memberAngle struct {
	cosAlpha, sinAlpha, cosOmega, sinOmega float64
}

type faceSet struct {
	front []string
	back  []string
}

// skinOptions mirrors the constructor parameters of SkinRenderer that the
// public API actually uses.
type skinOptions struct {
	ratio      float64
	headOnly   bool
	hR, vR     float64
	headHR     float64
	leftLegVR  float64
	rightLegVR float64
	leftArmVR  float64
	rightArmVR float64
	layers     bool
}

type skinRenderer struct {
	ratio      float64
	headOnly   bool
	hR, vR     float64
	headHR     float64
	leftLegVR  float64
	rightLegVR float64
	leftArmVR  float64
	rightArmVR float64
	layers     bool

	playerSkin    *gdImage
	isNewSkinType bool
	isAlex        bool
	hdRatio       float64

	alpha, omega                           float64
	cosAlpha, sinAlpha, cosOmega, sinOmega float64

	bounds

	memberAngles map[string]memberAngle
	visibleFaces map[string]faceSet
	allFaces     []string
	frontFaces   []string
	backFaces    []string

	polygons map[string]map[string][]*polygon
}

func newSkinRenderer(o skinOptions) *skinRenderer {
	return &skinRenderer{
		ratio:      o.ratio,
		headOnly:   o.headOnly,
		hR:         o.hR,
		vR:         o.vR,
		headHR:     o.headHR,
		leftLegVR:  o.leftLegVR,
		rightLegVR: o.rightLegVR,
		leftArmVR:  o.leftArmVR,
		rightArmVR: o.rightArmVR,
		layers:     o.layers,
	}
}

// render mirrors SkinRenderer::render.
func (r *skinRenderer) render(src image.Image, isAlex bool) *gdImage {
	r.playerSkin = fromImage(src)

	sourceWidth := r.playerSkin.w
	sourceHeight := r.playerSkin.h

	// Prevent memory overflow: internally downscale textures wider than 256px.
	// This is an internal rendering limit inherited from the frozen renderer,
	// not an upload restriction.
	if sourceWidth > 256 {
		newHeight := int(float64(sourceHeight) / (float64(sourceWidth) / 256))
		dest := newGDImage(256, newHeight)
		resample(dest, r.playerSkin, 0, 0, 0, 0, 256, newHeight, sourceWidth, sourceHeight)
		r.playerSkin = dest
	}

	r.isAlex = isAlex
	r.hdRatio = float64(r.playerSkin.w) / 64
	if r.playerSkin.w == r.playerSkin.h {
		r.isNewSkinType = true
	}

	r.makeBackgroundTransparent()

	// Quick fix for 1.8: copy the extra layers on top of the base layers.
	if r.layers {
		r.fixNewSkinTypeLayers()
	}

	r.calculateAngles()
	r.facesDetermination()
	r.generatePolygons()
	r.memberRotation()
	r.createProjectionPlan()

	return r.displayImage()
}

// makeBackgroundTransparent mirrors SkinRenderer::makeBackgroundTransparent.
//
// The frozen implementation decides whether the 8x8 top-left block is a single
// solid (non-transparent) color. If so, the base UV rectangles are pre-filled
// with that color; otherwise they are pre-filled with opaque black. The source
// texture is then alpha-blended over that pre-fill, so texels outside the base
// rectangles (overlay-only areas) stay transparent and transparent base texels
// reveal the fill color.
func (r *skinRenderer) makeBackgroundTransparent() {
	img := r.playerSkin
	var tempValue gdColor
	haveTemp := false
	needRemove := true

	for iH := 0; iH < 8; iH++ {
		for iV := 0; iV < 8; iV++ {
			if iH >= img.w || iV >= img.h {
				continue
			}
			pixelColor := img.pixel(iH, iV)
			if gdAlpha(pixelColor) > 120 {
				// The image contains transparency, nothing to do.
				needRemove = false
			}
			if !haveTemp {
				tempValue = pixelColor
				haveTemp = true
			} else if tempValue != pixelColor {
				// Cannot determine a background color, the file is probably fine.
				needRemove = false
			}
		}
	}

	imgX, imgY := img.w, img.h
	dst := newGDImage(imgX, imgY)

	var color gdColor
	if needRemove {
		color = gdRGBA(gdRed(tempValue), gdGreen(tempValue), gdBlue(tempValue), gdAlphaOpaque)
	} else {
		color = gdRGBA(0, 0, 0, gdAlphaOpaque)
	}

	positionMultiply := float64(imgX) / 64
	rect := func(x1, y1, x2, y2 float64) {
		dst.fillRect(
			int(x1*positionMultiply), int(y1*positionMultiply),
			int(x2*positionMultiply), int(y2*positionMultiply),
			color,
		)
	}

	// Head.
	rect(8, 0, 23, 7)
	rect(0, 8, 31, 15)

	// Right leg, body, right arm.
	rect(4, 16, 11, 19)
	rect(20, 16, 35, 19)
	rect(44, 16, 51, 19)
	rect(0, 20, 54, 31)

	// Left leg, left arm.
	rect(20, 48, 27, 51)
	rect(36, 48, 43, 51)
	rect(16, 52, 47, 63)

	blendCopy(dst, img, 0, 0, 0, 0, imgX, imgY)

	r.playerSkin = dst
}

// fixNewSkinTypeLayers mirrors SkinRenderer::fixNewSkinTypeLayers. Note that
// the copy offsets are expressed in 64x64 units, so HD textures copy the wrong
// area; this bug is preserved to stay pixel-compatible with the oracle.
func (r *skinRenderer) fixNewSkinTypeLayers() {
	if !r.isNewSkinType {
		return
	}
	img := r.playerSkin
	blendCopy(img, img, 0, 16, 0, 32, 56, 16)   // RL2, BODY2, RA2
	blendCopy(img, img, 16, 48, 0, 48, 16, 16)  // LL2
	blendCopy(img, img, 32, 48, 48, 48, 16, 16) // LA2
}

func (r *skinRenderer) calculateAngles() {
	r.alpha = r.vR * degToRad
	r.omega = r.hR * degToRad

	r.cosAlpha = math.Cos(r.alpha)
	r.sinAlpha = math.Sin(r.alpha)
	r.cosOmega = math.Cos(r.omega)
	r.sinOmega = math.Sin(r.omega)

	r.memberAngles = map[string]memberAngle{
		"torso": {math.Cos(0), math.Sin(0), math.Cos(0), math.Sin(0)},
	}

	alphaHead := 0.0
	omegaHead := r.headHR * degToRad
	head := memberAngle{math.Cos(alphaHead), math.Sin(alphaHead), math.Cos(omegaHead), math.Sin(omegaHead)}
	r.memberAngles["head"] = head
	r.memberAngles["helmet"] = head

	armAngle := func(deg float64) memberAngle {
		a := deg * degToRad
		return memberAngle{math.Cos(a), math.Sin(a), math.Cos(0), math.Sin(0)}
	}
	r.memberAngles["rightArm"] = armAngle(r.rightArmVR)
	r.memberAngles["leftArm"] = armAngle(r.leftArmVR)
	r.memberAngles["rightLeg"] = armAngle(r.rightLegVR)
	r.memberAngles["leftLeg"] = armAngle(r.leftLegVR)

	r.minX, r.maxX, r.minY, r.maxY = 0, 0, 0, 0
}

type cubePoint struct {
	p     *point
	faces []string
}

func newCubePoints() []cubePoint {
	mk := func(x, y, z float64, faces ...string) cubePoint {
		return cubePoint{p: newPoint(x, y, z), faces: faces}
	}
	return []cubePoint{
		mk(0, 0, 0, "back", "right", "top"),
		mk(0, 0, 1, "front", "right", "top"),
		mk(0, 1, 0, "back", "right", "bottom"),
		mk(0, 1, 1, "front", "right", "bottom"),
		mk(1, 0, 0, "back", "left", "top"),
		mk(1, 0, 1, "front", "left", "top"),
		mk(1, 1, 0, "back", "left", "bottom"),
		mk(1, 1, 1, "front", "left", "bottom"),
	}
}

func diffFaces(all, excluded []string) []string {
	out := make([]string, 0, len(all)-len(excluded))
	for _, face := range all {
		found := false
		for _, ex := range excluded {
			if face == ex {
				found = true
				break
			}
		}
		if !found {
			out = append(out, face)
		}
	}
	return out
}

func (r *skinRenderer) facesDetermination() {
	r.visibleFaces = make(map[string]faceSet, 6)
	r.allFaces = []string{"back", "right", "top", "front", "left", "bottom"}

	selectDeepest := func(points []cubePoint) []string {
		var best *cubePoint
		for i := range points {
			cp := &points[i]
			if best == nil || best.p.depth() > cp.p.depth() {
				best = cp
			}
		}
		if best == nil {
			return nil
		}
		return best.faces
	}

	for _, member := range []string{"head", "torso", "rightArm", "leftArm", "rightLeg", "leftLeg"} {
		angle := r.memberAngles[member]
		points := newCubePoints()
		for i := range points {
			points[i].p.preProject(0, 0, 0, angle.cosAlpha, angle.sinAlpha, angle.cosOmega, angle.sinOmega)
			points[i].p.project(r.cosAlpha, r.sinAlpha, r.cosOmega, r.sinOmega, &r.bounds)
		}
		back := selectDeepest(points)
		r.visibleFaces[member] = faceSet{front: diffFaces(r.allFaces, back), back: back}
	}

	points := newCubePoints()
	for i := range points {
		points[i].p.project(r.cosAlpha, r.sinAlpha, r.cosOmega, r.sinOmega, &r.bounds)
	}
	r.backFaces = selectDeepest(points)
	r.frontFaces = diffFaces(r.allFaces, r.backFaces)
}

// volume stores the per-part vertex grid. libgd's PHP implementation uses
// nested arrays keyed by (possibly float) coordinates; PHP truncates float
// array keys to integers, which this map reproduces.
type volume struct {
	pts map[[3]int]*point
}

func newVolume() *volume { return &volume{pts: make(map[[3]int]*point)} }

func volumeKey(i, j, k float64) [3]int {
	return [3]int{int(i), int(j), int(k)}
}

func (v *volume) has(i, j, k float64) bool {
	_, ok := v.pts[volumeKey(i, j, k)]
	return ok
}

func (v *volume) set(i, j, k, x, y, z float64) {
	v.pts[volumeKey(i, j, k)] = newPoint(x, y, z)
}

func (v *volume) ensure(i, j, k, x, y, z float64) {
	key := volumeKey(i, j, k)
	if _, ok := v.pts[key]; !ok {
		v.pts[key] = newPoint(x, y, z)
	}
}

func (v *volume) point(i, j, k float64) *point {
	if p, ok := v.pts[volumeKey(i, j, k)]; ok {
		return p
	}
	// The frozen PHP code would fail on a missing vertex. A fresh zero point
	// keeps degenerate (e.g. 1x1) textures from panicking.
	return newPoint(0, 0, 0)
}

// colorAt samples the working texture. PHP passes float coordinates to
// imagecolorat(), which truncates them to integers. Out-of-range samples are
// treated as fully transparent so malformed textures cannot panic; the frozen
// code emits a PHP warning and renders an opaque black polygon there.
func colorAt(im *gdImage, x, y float64) gdColor {
	xi, yi := int(x), int(y)
	if xi < 0 || yi < 0 || xi >= im.w || yi >= im.h {
		return gdRGBA(255, 255, 255, gdAlphaTransparent)
	}
	return im.px[yi*im.w+xi]
}

func quad(a, b, c, d *point) []*point { return []*point{a, b, c, d} }

func (r *skinRenderer) generatePolygons() {
	r.polygons = map[string]map[string][]*polygon{
		"helmet": {}, "head": {}, "torso": {}, "rightArm": {},
		"leftArm": {}, "rightLeg": {}, "leftLeg": {},
	}

	isAlex := r.isAlex
	hr := r.hdRatio
	img := r.playerSkin

	add := func(part, face string, dots []*point, color gdColor) {
		r.polygons[part][face] = append(r.polygons[part][face], &polygon{dots: dots, color: color})
	}

	// HEAD
	vp := newVolume()
	for i := 0; float64(i) < 9*hr; i++ {
		for j := 0; float64(j) < 9*hr; j++ {
			vp.ensure(float64(i), float64(j), -2*hr, float64(i), float64(j), -2*hr)
			vp.ensure(float64(i), float64(j), 6*hr, float64(i), float64(j), 6*hr)
		}
	}
	for j := 0; float64(j) < 9*hr; j++ {
		for k := -2 * hr; k < 7*hr; k++ {
			vp.ensure(0, float64(j), k, 0, float64(j), k)
			vp.ensure(8*hr, float64(j), k, 8*hr, float64(j), k)
		}
	}
	for i := 0; float64(i) < 9*hr; i++ {
		for k := -2 * hr; k < 7*hr; k++ {
			vp.ensure(float64(i), 0, k, float64(i), 0, k)
			vp.ensure(float64(i), 8*hr, k, float64(i), 8*hr, k)
		}
	}
	for i := 0; float64(i) < 8*hr; i++ {
		for j := 0; float64(j) < 8*hr; j++ {
			add("head", "back", quad(
				vp.point(float64(i), float64(j), -2*hr),
				vp.point(float64(i+1), float64(j), -2*hr),
				vp.point(float64(i+1), float64(j+1), -2*hr),
				vp.point(float64(i), float64(j+1), -2*hr),
			), colorAt(img, 32*hr-1-float64(i), 8*hr+float64(j)))
			add("head", "front", quad(
				vp.point(float64(i), float64(j), 6*hr),
				vp.point(float64(i+1), float64(j), 6*hr),
				vp.point(float64(i+1), float64(j+1), 6*hr),
				vp.point(float64(i), float64(j+1), 6*hr),
			), colorAt(img, 8*hr+float64(i), 8*hr+float64(j)))
		}
	}
	for j := 0; float64(j) < 8*hr; j++ {
		for k := -2 * hr; k < 6*hr; k++ {
			add("head", "right", quad(
				vp.point(0, float64(j), k),
				vp.point(0, float64(j), k+1),
				vp.point(0, float64(j+1), k+1),
				vp.point(0, float64(j+1), k),
			), colorAt(img, k+2*hr, 8*hr+float64(j)))
			add("head", "left", quad(
				vp.point(8*hr, float64(j), k),
				vp.point(8*hr, float64(j), k+1),
				vp.point(8*hr, float64(j+1), k+1),
				vp.point(8*hr, float64(j+1), k),
			), colorAt(img, (24*hr-1)-k-2*hr, 8*hr+float64(j)))
		}
	}
	for i := 0; float64(i) < 8*hr; i++ {
		for k := -2 * hr; k < 6*hr; k++ {
			add("head", "top", quad(
				vp.point(float64(i), 0, k),
				vp.point(float64(i+1), 0, k),
				vp.point(float64(i+1), 0, k+1),
				vp.point(float64(i), 0, k+1),
			), colorAt(img, 8*hr+float64(i), k+2*hr))
			add("head", "bottom", quad(
				vp.point(float64(i), 8*hr, k),
				vp.point(float64(i+1), 8*hr, k),
				vp.point(float64(i+1), 8*hr, k+1),
				vp.point(float64(i), 8*hr, k+1),
			), colorAt(img, 16*hr+float64(i), 2*hr+k))
		}
	}

	// HELMET / HAIR
	vp = newVolume()
	for i := 0; float64(i) < 9*hr; i++ {
		for j := 0; float64(j) < 9*hr; j++ {
			vp.ensure(float64(i), float64(j), -2*hr,
				float64(i)*9/8-0.5*hr, float64(j)*9/8-0.5*hr, -2.5*hr)
			vp.ensure(float64(i), float64(j), 6*hr,
				float64(i)*9/8-0.5*hr, float64(j)*9/8-0.5*hr, 6.5*hr)
		}
	}
	for j := 0; float64(j) < 9*hr; j++ {
		for k := -2 * hr; k < 7*hr; k++ {
			vp.ensure(0, float64(j), k,
				-0.5*hr, float64(j)*9/8-0.5*hr, k*9/8-0.5*hr)
			vp.ensure(8*hr, float64(j), k,
				8.5*hr, float64(j)*9/8-0.5*hr, k*9/8-0.5*hr)
		}
	}
	for i := 0; float64(i) < 9*hr; i++ {
		for k := -2 * hr; k < 7*hr; k++ {
			vp.ensure(float64(i), 0, k,
				float64(i)*9/8-0.5*hr, -0.5*hr, k*9/8-0.5*hr)
			vp.ensure(float64(i), 8*hr, k,
				float64(i)*9/8-0.5*hr, 8.5*hr, k*9/8-0.5*hr)
		}
	}
	for i := 0; float64(i) < 8*hr; i++ {
		for j := 0; float64(j) < 8*hr; j++ {
			add("helmet", "back", quad(
				vp.point(float64(i), float64(j), -2*hr),
				vp.point(float64(i+1), float64(j), -2*hr),
				vp.point(float64(i+1), float64(j+1), -2*hr),
				vp.point(float64(i), float64(j+1), -2*hr),
			), colorAt(img, 32*hr+(32*hr-1)-float64(i), 8*hr+float64(j)))
			add("helmet", "front", quad(
				vp.point(float64(i), float64(j), 6*hr),
				vp.point(float64(i+1), float64(j), 6*hr),
				vp.point(float64(i+1), float64(j+1), 6*hr),
				vp.point(float64(i), float64(j+1), 6*hr),
			), colorAt(img, 32*hr+8*hr+float64(i), 8*hr+float64(j)))
		}
	}
	for j := 0; float64(j) < 8*hr; j++ {
		for k := -2 * hr; k < 6*hr; k++ {
			add("helmet", "right", quad(
				vp.point(0, float64(j), k),
				vp.point(0, float64(j), k+1),
				vp.point(0, float64(j+1), k+1),
				vp.point(0, float64(j+1), k),
			), colorAt(img, 32*hr+k+2*hr, 8*hr+float64(j)))
			add("helmet", "left", quad(
				vp.point(8*hr, float64(j), k),
				vp.point(8*hr, float64(j), k+1),
				vp.point(8*hr, float64(j+1), k+1),
				vp.point(8*hr, float64(j+1), k),
			), colorAt(img, 32*hr+(24*hr-1)-k-2*hr, 8*hr+float64(j)))
		}
	}
	for i := 0; float64(i) < 8*hr; i++ {
		for k := -2 * hr; k < 6*hr; k++ {
			add("helmet", "top", quad(
				vp.point(float64(i), 0, k),
				vp.point(float64(i+1), 0, k),
				vp.point(float64(i+1), 0, k+1),
				vp.point(float64(i), 0, k+1),
			), colorAt(img, 32*hr+8*hr+float64(i), k+2*hr))
			add("helmet", "bottom", quad(
				vp.point(float64(i), 8*hr, k),
				vp.point(float64(i+1), 8*hr, k),
				vp.point(float64(i+1), 8*hr, k+1),
				vp.point(float64(i), 8*hr, k+1),
			), colorAt(img, 32*hr+16*hr+float64(i), 2*hr+k))
		}
	}

	if r.headOnly {
		return
	}

	// TORSO
	vp = newVolume()
	for i := 0; float64(i) < 9*hr; i++ {
		for j := 0; float64(j) < 13*hr; j++ {
			vp.ensure(float64(i), float64(j), 0, float64(i), float64(j)+8*hr, 0)
			vp.ensure(float64(i), float64(j), 4*hr, float64(i), float64(j)+8*hr, 4*hr)
		}
	}
	for j := 0; float64(j) < 13*hr; j++ {
		for k := 0; float64(k) < 5*hr; k++ {
			vp.ensure(0, float64(j), float64(k), 0, float64(j)+8*hr, float64(k))
			vp.ensure(8*hr, float64(j), float64(k), 8*hr, float64(j)+8*hr, float64(k))
		}
	}
	for i := 0; float64(i) < 9*hr; i++ {
		for k := 0; float64(k) < 5*hr; k++ {
			vp.ensure(float64(i), 0, float64(k), float64(i), 8*hr, float64(k))
			vp.ensure(float64(i), 12*hr, float64(k), float64(i), 12*hr+8*hr, float64(k))
		}
	}
	for i := 0; float64(i) < 8*hr; i++ {
		for j := 0; float64(j) < 12*hr; j++ {
			add("torso", "back", quad(
				vp.point(float64(i), float64(j), 0),
				vp.point(float64(i+1), float64(j), 0),
				vp.point(float64(i+1), float64(j+1), 0),
				vp.point(float64(i), float64(j+1), 0),
			), colorAt(img, (40*hr-1)-float64(i), 20*hr+float64(j)))
			add("torso", "front", quad(
				vp.point(float64(i), float64(j), 4*hr),
				vp.point(float64(i+1), float64(j), 4*hr),
				vp.point(float64(i+1), float64(j+1), 4*hr),
				vp.point(float64(i), float64(j+1), 4*hr),
			), colorAt(img, 20*hr+float64(i), 20*hr+float64(j)))
		}
	}
	for j := 0; float64(j) < 12*hr; j++ {
		for k := 0; float64(k) < 4*hr; k++ {
			add("torso", "right", quad(
				vp.point(0, float64(j), float64(k)),
				vp.point(0, float64(j), float64(k+1)),
				vp.point(0, float64(j+1), float64(k+1)),
				vp.point(0, float64(j+1), float64(k)),
			), colorAt(img, 16*hr+float64(k), 20*hr+float64(j)))
			add("torso", "left", quad(
				vp.point(8*hr, float64(j), float64(k)),
				vp.point(8*hr, float64(j), float64(k+1)),
				vp.point(8*hr, float64(j+1), float64(k+1)),
				vp.point(8*hr, float64(j+1), float64(k)),
			), colorAt(img, (32*hr-1)-float64(k), 20*hr+float64(j)))
		}
	}
	for i := 0; float64(i) < 8*hr; i++ {
		for k := 0; float64(k) < 4*hr; k++ {
			add("torso", "top", quad(
				vp.point(float64(i), 0, float64(k)),
				vp.point(float64(i+1), 0, float64(k)),
				vp.point(float64(i+1), 0, float64(k+1)),
				vp.point(float64(i), 0, float64(k+1)),
			), colorAt(img, 20*hr+float64(i), 16*hr+float64(k)))
			add("torso", "bottom", quad(
				vp.point(float64(i), 12*hr, float64(k)),
				vp.point(float64(i+1), 12*hr, float64(k)),
				vp.point(float64(i+1), 12*hr, float64(k+1)),
				vp.point(float64(i), 12*hr, float64(k+1)),
			), colorAt(img, 28*hr+float64(i), (20*hr-1)-float64(k)))
		}
	}

	// RIGHT ARM
	vp = newVolume()
	for i := 0; float64(i) < 9*hr; i++ {
		for j := 0; float64(j) < 13*hr; j++ {
			vp.ensure(float64(i), float64(j), 0, float64(i)-4*hr, float64(j)+8*hr, 0)
			vp.ensure(float64(i), float64(j), 4*hr, float64(i)-4*hr, float64(j)+8*hr, 4*hr)
		}
	}
	for j := 0; float64(j) < 13*hr; j++ {
		for k := 0; float64(k) < 5*hr; k++ {
			vp.ensure(0, float64(j), float64(k), 0-4*hr, float64(j)+8*hr, float64(k))
			if !vp.has(8*hr, float64(j), float64(k)) {
				vp.set(4*hr, float64(j), float64(k), 4*hr-4*hr, float64(j)+8*hr, float64(k))
			}
		}
	}
	for i := 0; float64(i) < 9*hr; i++ {
		for k := 0; float64(k) < 5*hr; k++ {
			vp.ensure(float64(i), 0, float64(k), float64(i)-4*hr, 8*hr, float64(k))
			vp.ensure(float64(i), 12*hr, float64(k), float64(i)-4*hr, 12*hr+8*hr, float64(k))
		}
	}
	if isAlex {
		for i := 0; float64(i) < 3*hr; i++ {
			for j := 0; float64(j) < 12*hr; j++ {
				add("rightArm", "back", quad(
					vp.point(float64(i), float64(j), 0),
					vp.point(float64(i+1), float64(j), 0),
					vp.point(float64(i+1), float64(j+1), 0),
					vp.point(float64(i), float64(j+1), 0),
				), colorAt(img, (51*hr-1)-float64(i), 20*hr+float64(j)))
				add("rightArm", "front", quad(
					vp.point(float64(i), float64(j), 4*hr),
					vp.point(float64(i+1), float64(j), 4*hr),
					vp.point(float64(i+1), float64(j+1), 4*hr),
					vp.point(float64(i), float64(j+1), 4*hr),
				), colorAt(img, 44*hr+float64(i), 20*hr+float64(j)))
			}
		}
	} else {
		for i := 0; float64(i) < 4*hr; i++ {
			for j := 0; float64(j) < 12*hr; j++ {
				add("rightArm", "back", quad(
					vp.point(float64(i), float64(j), 0),
					vp.point(float64(i+1), float64(j), 0),
					vp.point(float64(i+1), float64(j+1), 0),
					vp.point(float64(i), float64(j+1), 0),
				), colorAt(img, (56*hr-1)-float64(i), 20*hr+float64(j)))
				add("rightArm", "front", quad(
					vp.point(float64(i), float64(j), 4*hr),
					vp.point(float64(i+1), float64(j), 4*hr),
					vp.point(float64(i+1), float64(j+1), 4*hr),
					vp.point(float64(i), float64(j+1), 4*hr),
				), colorAt(img, 44*hr+float64(i), 20*hr+float64(j)))
			}
		}
	}
	for j := 0; float64(j) < 12*hr; j++ {
		for k := 0; float64(k) < 4*hr; k++ {
			rightOffsetX := 40.0
			if isAlex {
				rightOffsetX = 47
			}
			add("rightArm", "right", quad(
				vp.point(0, float64(j), float64(k)),
				vp.point(0, float64(j), float64(k+1)),
				vp.point(0, float64(j+1), float64(k+1)),
				vp.point(0, float64(j+1), float64(k)),
			), colorAt(img, rightOffsetX*hr+float64(k), 20*hr+float64(j)))
			leftOffsetX := 52.0
			if isAlex {
				leftOffsetX = 40
			}
			add("rightArm", "left", quad(
				vp.point(4*hr, float64(j), float64(k)),
				vp.point(4*hr, float64(j), float64(k+1)),
				vp.point(4*hr, float64(j+1), float64(k+1)),
				vp.point(4*hr, float64(j+1), float64(k)),
			), colorAt(img, (leftOffsetX-1)*hr-float64(k), 20*hr+float64(j)))
		}
	}
	if isAlex {
		for i := 0; float64(i) < 3*hr; i++ {
			for k := 0; float64(k) < 4*hr; k++ {
				add("rightArm", "top", quad(
					vp.point(float64(i), 0, float64(k)),
					vp.point(float64(i+1), 0, float64(k)),
					vp.point(float64(i+1), 0, float64(k+1)),
					vp.point(float64(i), 0, float64(k+1)),
				), colorAt(img, 44*hr+float64(i), 16*hr+float64(k)))
				add("rightArm", "bottom", quad(
					vp.point(float64(i), 12*hr, float64(k)),
					vp.point(float64(i+1), 12*hr, float64(k)),
					vp.point(float64(i+1), 12*hr, float64(k+1)),
					vp.point(float64(i), 12*hr, float64(k+1)),
				), colorAt(img, 47*hr+float64(i), 16*hr+float64(k)))
			}
		}
	} else {
		for i := 0; float64(i) < 4*hr; i++ {
			for k := 0; float64(k) < 4*hr; k++ {
				add("rightArm", "top", quad(
					vp.point(float64(i), 0, float64(k)),
					vp.point(float64(i+1), 0, float64(k)),
					vp.point(float64(i+1), 0, float64(k+1)),
					vp.point(float64(i), 0, float64(k+1)),
				), colorAt(img, 44*hr+float64(i), 16*hr+float64(k)))
				add("rightArm", "bottom", quad(
					vp.point(float64(i), 12*hr, float64(k)),
					vp.point(float64(i+1), 12*hr, float64(k)),
					vp.point(float64(i+1), 12*hr, float64(k+1)),
					vp.point(float64(i), 12*hr, float64(k+1)),
				), colorAt(img, 48*hr+float64(i), 16*hr+float64(k)))
			}
		}
	}

	// LEFT ARM
	vp = newVolume()
	for i := 0; float64(i) < 9*hr; i++ {
		for j := 0; float64(j) < 13*hr; j++ {
			vp.ensure(float64(i), float64(j), 0, float64(i)+8*hr, float64(j)+8*hr, 0)
			vp.ensure(float64(i), float64(j), 4*hr, float64(i)+8*hr, float64(j)+8*hr, 4*hr)
		}
	}
	for j := 0; float64(j) < 13*hr; j++ {
		for k := 0; float64(k) < 5*hr; k++ {
			vp.ensure(0, float64(j), float64(k), 8*hr, float64(j)+8*hr, float64(k))
			if !vp.has(8*hr, float64(j), float64(k)) {
				vp.set(4*hr, float64(j), float64(k), 4*hr+8*hr, float64(j)+8*hr, float64(k))
			}
		}
	}
	for i := 0; float64(i) < 9*hr; i++ {
		for k := 0; float64(k) < 5*hr; k++ {
			vp.ensure(float64(i), 0, float64(k), float64(i)+8*hr, 8*hr, float64(k))
			vp.ensure(float64(i), 12*hr, float64(k), float64(i)+8*hr, 12*hr+8*hr, float64(k))
		}
	}
	if isAlex {
		for i := 0; float64(i) < 3*hr; i++ {
			for j := 0; float64(j) < 12*hr; j++ {
				add("leftArm", "back", quad(
					vp.point(float64(i), float64(j), 0),
					vp.point(float64(i+1), float64(j), 0),
					vp.point(float64(i+1), float64(j+1), 0),
					vp.point(float64(i), float64(j+1), 0),
				), colorAt(img, 43*hr+float64(i), 52*hr+float64(j)))
				add("leftArm", "front", quad(
					vp.point(float64(i), float64(j), 4*hr),
					vp.point(float64(i+1), float64(j), 4*hr),
					vp.point(float64(i+1), float64(j+1), 4*hr),
					vp.point(float64(i), float64(j+1), 4*hr),
				), colorAt(img, 36*hr+float64(i), 52*hr+float64(j)))
			}
		}
	} else {
		for i := 0; float64(i) < 4*hr; i++ {
			for j := 0; float64(j) < 12*hr; j++ {
				var color1, color2 gdColor
				if r.isNewSkinType {
					color1 = colorAt(img, 47*hr-float64(i), 52*hr+float64(j))
					color2 = colorAt(img, 36*hr+float64(i), 52*hr+float64(j))
				} else {
					color1 = colorAt(img, (56*hr-1)-((4*hr-1)-float64(i)), 20*hr+float64(j))
					color2 = colorAt(img, 44*hr+((4*hr-1)-float64(i)), 20*hr+float64(j))
				}
				add("leftArm", "back", quad(
					vp.point(float64(i), float64(j), 0),
					vp.point(float64(i+1), float64(j), 0),
					vp.point(float64(i+1), float64(j+1), 0),
					vp.point(float64(i), float64(j+1), 0),
				), color1)
				add("leftArm", "front", quad(
					vp.point(float64(i), float64(j), 4*hr),
					vp.point(float64(i+1), float64(j), 4*hr),
					vp.point(float64(i+1), float64(j+1), 4*hr),
					vp.point(float64(i), float64(j+1), 4*hr),
				), color2)
			}
		}
	}
	for j := 0; float64(j) < 12*hr; j++ {
		for k := 0; float64(k) < 4*hr; k++ {
			var color1, color2 gdColor
			if r.isNewSkinType {
				color1 = colorAt(img, 32*hr+float64(k), 52*hr+float64(j))
				color2 = colorAt(img, 43*hr-float64(k), 52*hr+float64(j))
			} else {
				color1 = colorAt(img, 40*hr+((4*hr-1)-float64(k)), 20*hr+float64(j))
				color2 = colorAt(img, (52*hr-1)-((4*hr-1)-float64(k)), 20*hr+float64(j))
			}
			add("leftArm", "right", quad(
				vp.point(0, float64(j), float64(k)),
				vp.point(0, float64(j), float64(k+1)),
				vp.point(0, float64(j+1), float64(k+1)),
				vp.point(0, float64(j+1), float64(k)),
			), color1)
			add("leftArm", "left", quad(
				vp.point(4*hr, float64(j), float64(k)),
				vp.point(4*hr, float64(j), float64(k+1)),
				vp.point(4*hr, float64(j+1), float64(k+1)),
				vp.point(4*hr, float64(j+1), float64(k)),
			), color2)
		}
	}
	if isAlex {
		for i := 0; float64(i) < 3*hr; i++ {
			for k := 0; float64(k) < 4*hr; k++ {
				add("leftArm", "top", quad(
					vp.point(float64(i), 0, float64(k)),
					vp.point(float64(i+1), 0, float64(k)),
					vp.point(float64(i+1), 0, float64(k+1)),
					vp.point(float64(i), 0, float64(k+1)),
				), colorAt(img, 36*hr+float64(i), 48*hr+float64(k)))
				add("leftArm", "bottom", quad(
					vp.point(float64(i), 12*hr, float64(k)),
					vp.point(float64(i+1), 12*hr, float64(k)),
					vp.point(float64(i+1), 12*hr, float64(k+1)),
					vp.point(float64(i), 12*hr, float64(k+1)),
				), colorAt(img, 39*hr+float64(i), 48*hr+float64(k)))
			}
		}
	} else {
		for i := 0; float64(i) < 4*hr; i++ {
			for k := 0; float64(k) < 4*hr; k++ {
				var color1, color2 gdColor
				if r.isNewSkinType {
					color1 = colorAt(img, 36*hr+float64(i), 48*hr+float64(k))
					color2 = colorAt(img, 40*hr+float64(i), 48*hr+float64(k))
				} else {
					color1 = colorAt(img, 44*hr+((4*hr-1)-float64(i)), 16*hr+float64(k))
					color2 = colorAt(img, 48*hr+((4*hr-1)-float64(i)), (20*hr-1)-float64(k))
				}
				add("leftArm", "top", quad(
					vp.point(float64(i), 0, float64(k)),
					vp.point(float64(i+1), 0, float64(k)),
					vp.point(float64(i+1), 0, float64(k+1)),
					vp.point(float64(i), 0, float64(k+1)),
				), color1)
				add("leftArm", "bottom", quad(
					vp.point(float64(i), 12*hr, float64(k)),
					vp.point(float64(i+1), 12*hr, float64(k)),
					vp.point(float64(i+1), 12*hr, float64(k+1)),
					vp.point(float64(i), 12*hr, float64(k+1)),
				), color2)
			}
		}
	}

	// RIGHT LEG
	vp = newVolume()
	for i := 0; float64(i) < 9*hr; i++ {
		for j := 0; float64(j) < 13*hr; j++ {
			vp.ensure(float64(i), float64(j), 0, float64(i), float64(j)+20*hr, 0)
			vp.ensure(float64(i), float64(j), 4*hr, float64(i), float64(j)+20*hr, 4*hr)
		}
	}
	for j := 0; float64(j) < 13*hr; j++ {
		for k := 0; float64(k) < 5*hr; k++ {
			vp.ensure(0, float64(j), float64(k), 0, float64(j)+20*hr, float64(k))
			if !vp.has(8*hr, float64(j), float64(k)) {
				vp.set(4*hr, float64(j), float64(k), 4*hr, float64(j)+20*hr, float64(k))
			}
		}
	}
	for i := 0; float64(i) < 9*hr; i++ {
		for k := 0; float64(k) < 5*hr; k++ {
			vp.ensure(float64(i), 0, float64(k), float64(i), 20*hr, float64(k))
			vp.ensure(float64(i), 12*hr, float64(k), float64(i), 12*hr+20*hr, float64(k))
		}
	}
	for i := 0; float64(i) < 4*hr; i++ {
		for j := 0; float64(j) < 12*hr; j++ {
			add("rightLeg", "back", quad(
				vp.point(float64(i), float64(j), 0),
				vp.point(float64(i+1), float64(j), 0),
				vp.point(float64(i+1), float64(j+1), 0),
				vp.point(float64(i), float64(j+1), 0),
			), colorAt(img, (16*hr-1)-float64(i), 20*hr+float64(j)))
			add("rightLeg", "front", quad(
				vp.point(float64(i), float64(j), 4*hr),
				vp.point(float64(i+1), float64(j), 4*hr),
				vp.point(float64(i+1), float64(j+1), 4*hr),
				vp.point(float64(i), float64(j+1), 4*hr),
			), colorAt(img, 4*hr+float64(i), 20*hr+float64(j)))
		}
	}
	for j := 0; float64(j) < 12*hr; j++ {
		for k := 0; float64(k) < 4*hr; k++ {
			add("rightLeg", "right", quad(
				vp.point(0, float64(j), float64(k)),
				vp.point(0, float64(j), float64(k+1)),
				vp.point(0, float64(j+1), float64(k+1)),
				vp.point(0, float64(j+1), float64(k)),
			), colorAt(img, 0+float64(k), 20*hr+float64(j)))
			add("rightLeg", "left", quad(
				vp.point(4*hr, float64(j), float64(k)),
				vp.point(4*hr, float64(j), float64(k+1)),
				vp.point(4*hr, float64(j+1), float64(k+1)),
				vp.point(4*hr, float64(j+1), float64(k)),
			), colorAt(img, (12*hr-1)-float64(k), 20*hr+float64(j)))
		}
	}
	for i := 0; float64(i) < 4*hr; i++ {
		for k := 0; float64(k) < 4*hr; k++ {
			add("rightLeg", "top", quad(
				vp.point(float64(i), 0, float64(k)),
				vp.point(float64(i+1), 0, float64(k)),
				vp.point(float64(i+1), 0, float64(k+1)),
				vp.point(float64(i), 0, float64(k+1)),
			), colorAt(img, 4*hr+float64(i), 16*hr+float64(k)))
			add("rightLeg", "bottom", quad(
				vp.point(float64(i), 12*hr, float64(k)),
				vp.point(float64(i+1), 12*hr, float64(k)),
				vp.point(float64(i+1), 12*hr, float64(k+1)),
				vp.point(float64(i), 12*hr, float64(k+1)),
			), colorAt(img, 8*hr+float64(i), 16*hr+float64(k)))
		}
	}

	// LEFT LEG
	vp = newVolume()
	for i := 0; float64(i) < 9*hr; i++ {
		for j := 0; float64(j) < 13*hr; j++ {
			vp.ensure(float64(i), float64(j), 0, float64(i)+4*hr, float64(j)+20*hr, 0)
			vp.ensure(float64(i), float64(j), 4*hr, float64(i)+4*hr, float64(j)+20*hr, 4*hr)
		}
	}
	for j := 0; float64(j) < 13*hr; j++ {
		for k := 0; float64(k) < 5*hr; k++ {
			vp.ensure(0, float64(j), float64(k), 0+4*hr, float64(j)+20*hr, float64(k))
			if !vp.has(8*hr, float64(j), float64(k)) {
				vp.set(4*hr, float64(j), float64(k), 4*hr+4*hr, float64(j)+20*hr, float64(k))
			}
		}
	}
	for i := 0; float64(i) < 9*hr; i++ {
		for k := 0; float64(k) < 5*hr; k++ {
			vp.ensure(float64(i), 0, float64(k), float64(i)+4*hr, 20*hr, float64(k))
			vp.ensure(float64(i), 12*hr, float64(k), float64(i)+4*hr, 12*hr+20*hr, float64(k))
		}
	}
	for i := 0; float64(i) < 4*hr; i++ {
		for j := 0; float64(j) < 12*hr; j++ {
			var color1, color2 gdColor
			if r.isNewSkinType {
				color1 = colorAt(img, 31*hr-float64(i), 52*hr+float64(j))
				color2 = colorAt(img, 20*hr+float64(i), 52*hr+float64(j))
			} else {
				color1 = colorAt(img, (16*hr-1)-((4*hr-1)-float64(i)), 20*hr+float64(j))
				color2 = colorAt(img, 4*hr+((4*hr-1)-float64(i)), 20*hr+float64(j))
			}
			add("leftLeg", "back", quad(
				vp.point(float64(i), float64(j), 0),
				vp.point(float64(i+1), float64(j), 0),
				vp.point(float64(i+1), float64(j+1), 0),
				vp.point(float64(i), float64(j+1), 0),
			), color1)
			add("leftLeg", "front", quad(
				vp.point(float64(i), float64(j), 4*hr),
				vp.point(float64(i+1), float64(j), 4*hr),
				vp.point(float64(i+1), float64(j+1), 4*hr),
				vp.point(float64(i), float64(j+1), 4*hr),
			), color2)
		}
	}
	for j := 0; float64(j) < 12*hr; j++ {
		for k := 0; float64(k) < 4*hr; k++ {
			var color1, color2 gdColor
			if r.isNewSkinType {
				color1 = colorAt(img, 16*hr+float64(k), 52*hr+float64(j))
				color2 = colorAt(img, 27*hr-float64(k), 52*hr+float64(j))
			} else {
				color1 = colorAt(img, 0+((4*hr-1)-float64(k)), 20*hr+float64(j))
				color2 = colorAt(img, (12*hr-1)-((4*hr-1)-float64(k)), 20*hr+float64(j))
			}
			add("leftLeg", "right", quad(
				vp.point(0, float64(j), float64(k)),
				vp.point(0, float64(j), float64(k+1)),
				vp.point(0, float64(j+1), float64(k+1)),
				vp.point(0, float64(j+1), float64(k)),
			), color1)
			add("leftLeg", "left", quad(
				vp.point(4*hr, float64(j), float64(k)),
				vp.point(4*hr, float64(j), float64(k+1)),
				vp.point(4*hr, float64(j+1), float64(k+1)),
				vp.point(4*hr, float64(j+1), float64(k)),
			), color2)
		}
	}
	for i := 0; float64(i) < 4*hr; i++ {
		for k := 0; float64(k) < 4*hr; k++ {
			var color1, color2 gdColor
			if r.isNewSkinType {
				color1 = colorAt(img, 20*hr+float64(i), 48*hr+float64(k))
				color2 = colorAt(img, 24*hr+float64(i), 48*hr+float64(k))
			} else {
				color1 = colorAt(img, 4*hr+((4*hr-1)-float64(i)), 16*hr+float64(k))
				color2 = colorAt(img, 8*hr+((4*hr-1)-float64(i)), (20*hr-1)-float64(k))
			}
			add("leftLeg", "top", quad(
				vp.point(float64(i), 0, float64(k)),
				vp.point(float64(i+1), 0, float64(k)),
				vp.point(float64(i+1), 0, float64(k+1)),
				vp.point(float64(i), 0, float64(k+1)),
			), color1)
			add("leftLeg", "bottom", quad(
				vp.point(float64(i), 12*hr, float64(k)),
				vp.point(float64(i+1), 12*hr, float64(k)),
				vp.point(float64(i+1), 12*hr, float64(k+1)),
				vp.point(float64(i), 12*hr, float64(k+1)),
			), color2)
		}
	}
}

func (r *skinRenderer) memberRotation() {
	rotate := func(part string, dx, dy, dz float64) {
		angle := r.memberAngles[part]
		for _, face := range r.polygons[part] {
			for _, poly := range face {
				for _, dot := range poly.dots {
					dot.preProject(dx, dy, dz, angle.cosAlpha, angle.sinAlpha, angle.cosOmega, angle.sinOmega)
				}
			}
		}
	}

	rotate("head", 4, 8, 2)
	rotate("helmet", 4, 8, 2)
	if r.headOnly {
		return
	}
	rotate("rightArm", -2, 8, 2)
	rotate("leftArm", 10, 8, 2)

	rightLegDZ := 4.0
	if r.memberAngles["rightLeg"].sinAlpha < 0 {
		rightLegDZ = 0
	}
	rotate("rightLeg", 2, 20, rightLegDZ)

	leftLegDZ := 4.0
	if r.memberAngles["leftLeg"].sinAlpha < 0 {
		leftLegDZ = 0
	}
	rotate("leftLeg", 6, 20, leftLegDZ)
}

func (r *skinRenderer) createProjectionPlan() {
	for _, piece := range r.polygons {
		for _, face := range piece {
			for _, poly := range face {
				for _, dot := range poly.dots {
					if !dot.projected {
						dot.project(r.cosAlpha, r.sinAlpha, r.cosOmega, r.sinOmega, &r.bounds)
					}
				}
			}
		}
	}
}

func (r *skinRenderer) displayImage() *gdImage {
	width := r.maxX - r.minX
	height := r.maxY - r.minY
	ratio := r.ratio * 2

	srcWidth := int(ratio*width + 1)
	srcHeight := int(ratio*height + 1)
	if srcWidth < 1 {
		srcWidth = 1
	}
	if srcHeight < 1 {
		srcHeight = 1
	}

	image := newGDImage(srcWidth, srcHeight)

	for _, piece := range r.displayOrder() {
		for _, face := range piece.faces {
			for _, poly := range r.polygons[piece.part][face] {
				poly.addPngPolygon(image, r.minX, r.minY, ratio)
			}
		}
	}

	// Anti-aliasing: downsample by 2 exactly like the frozen renderer.
	realWidth := int(float64(srcWidth) / 2)
	realHeight := int(float64(srcHeight) / 2)
	if realWidth < 1 {
		realWidth = 1
	}
	if realHeight < 1 {
		realHeight = 1
	}
	destImage := newGDImage(realWidth, realHeight)
	resample(destImage, image, 0, 0, 0, 0, realWidth, realHeight, srcWidth, srcHeight)

	return destImage
}

type partFaces struct {
	part  string
	faces []string
}

func containsFace(faces []string, face string) bool {
	for _, f := range faces {
		if f == face {
			return true
		}
	}
	return false
}

// displayOrder mirrors SkinRenderer::getDisplayOrder.
func (r *skinRenderer) displayOrder() []partFaces {
	var order []partFaces

	if containsFace(r.frontFaces, "top") {
		if containsFace(r.frontFaces, "right") {
			order = append(order,
				partFaces{"leftLeg", r.backFaces},
				partFaces{"leftLeg", r.visibleFaces["leftLeg"].front},
				partFaces{"rightLeg", r.backFaces},
				partFaces{"rightLeg", r.visibleFaces["rightLeg"].front},
				partFaces{"leftArm", r.backFaces},
				partFaces{"leftArm", r.visibleFaces["leftArm"].front},
				partFaces{"torso", r.backFaces},
				partFaces{"torso", r.visibleFaces["torso"].front},
				partFaces{"rightArm", r.backFaces},
				partFaces{"rightArm", r.visibleFaces["rightArm"].front},
			)
		} else {
			order = append(order,
				partFaces{"rightLeg", r.backFaces},
				partFaces{"rightLeg", r.visibleFaces["rightLeg"].front},
				partFaces{"leftLeg", r.backFaces},
				partFaces{"leftLeg", r.visibleFaces["leftLeg"].front},
				partFaces{"rightArm", r.backFaces},
				partFaces{"rightArm", r.visibleFaces["rightArm"].front},
				partFaces{"torso", r.backFaces},
				partFaces{"torso", r.visibleFaces["torso"].front},
				partFaces{"leftArm", r.backFaces},
				partFaces{"leftArm", r.visibleFaces["leftArm"].front},
			)
		}
		order = append(order,
			partFaces{"helmet", r.backFaces},
			partFaces{"head", r.backFaces},
			partFaces{"head", r.visibleFaces["head"].front},
			partFaces{"helmet", r.visibleFaces["head"].front},
		)
	} else {
		order = append(order,
			partFaces{"helmet", r.backFaces},
			partFaces{"head", r.backFaces},
			partFaces{"head", r.visibleFaces["head"].front},
			partFaces{"helmet", r.visibleFaces["head"].front},
		)
		if containsFace(r.frontFaces, "right") {
			order = append(order,
				partFaces{"leftArm", r.backFaces},
				partFaces{"leftArm", r.visibleFaces["leftArm"].front},
				partFaces{"torso", r.backFaces},
				partFaces{"torso", r.visibleFaces["torso"].front},
				partFaces{"rightArm", r.backFaces},
				partFaces{"rightArm", r.visibleFaces["rightArm"].front},
				partFaces{"leftLeg", r.backFaces},
				partFaces{"leftLeg", r.visibleFaces["leftLeg"].front},
				partFaces{"rightLeg", r.backFaces},
				partFaces{"rightLeg", r.visibleFaces["rightLeg"].front},
			)
		} else {
			order = append(order,
				partFaces{"rightArm", r.backFaces},
				partFaces{"rightArm", r.visibleFaces["rightArm"].front},
				partFaces{"torso", r.backFaces},
				partFaces{"torso", r.visibleFaces["torso"].front},
				partFaces{"leftArm", r.backFaces},
				partFaces{"leftArm", r.visibleFaces["leftArm"].front},
				partFaces{"rightLeg", r.backFaces},
				partFaces{"rightLeg", r.visibleFaces["rightLeg"].front},
				partFaces{"leftLeg", r.backFaces},
				partFaces{"leftLeg", r.visibleFaces["leftLeg"].front},
			)
		}
	}

	return order
}
