// Package renderer renders Minecraft skin and cape textures as images.
//
// It is a pure-Go port of the frozen Blessing Skin 6.0.2 PHP renderer
// (blessing/texture-renderer), which is vendored read-only under
// .local/refactoring/reference-src/6.0.2/vendor/blessing/texture-renderer.
// The port keeps the original UV mapping, the Alex (slim) arm switch, the
// legacy 64x32 and modern 64x64 layouts, overlay handling, visible-face
// selection, draw order and projection, and the original internal downscale of
// textures wider than 256 pixels. Rendering uses only the Go standard library.
//
// The output is pixel-compatible with the PHP oracle for the checked fixtures,
// including libgd's 7-bit alpha quantisation, scanline polygon rasteriser and
// area-weighted imagecopyresampled anti-aliasing step. See the M3-06 renderer
// evidence directory for the per-fixture comparison report.
//
// Original licenses:
//
// The ported PHP implementation is MIT licensed:
//
//	Copyright (c) 2020-present The Blessing Skin Team
//
// The Minecraft skin rendering algorithm derives from the PHP Minecraft Skin
// Renderer by Pierre Gros, which is BSD licensed:
//
//	Copyright (c) 2012, Pierre Gros
//
// The full license texts are shipped in LICENSE-MIT and LICENSE-BSD in this
// directory.
package renderer

import "image"

// skinOptionsForAPI builds the renderer options used by the public entry points.
// The frozen Minecraft facade fixes these values:
//
//	renderSkin:      SkinRenderer(ratio, headOnly=false, hR=-45/135, vR=-25)
//	render2dAvatar:  SkinRenderer(ratio, headOnly=true,  hR=0,   vR=0)
//	render3dAvatar:  SkinRenderer(ratio, headOnly=true,  hR=45,  vR=-25)
func skinOptionsForAPI(ratio float64, headOnly bool, hR, vR float64) skinOptions {
	return skinOptions{ratio: ratio, headOnly: headOnly, hR: hR, vR: vR, layers: true}
}

func clampRatio(ratio int) float64 {
	if ratio < 1 {
		return 1
	}
	return float64(ratio)
}

// Skin renders the same preview image as Minecraft::renderSkin in the frozen
// 6.0.2 renderer: the model seen from the back and the front, side by side on
// a transparent canvas. ratio=12 reproduces the original preview size; slim
// selects the 3-pixel Alex arms.
func Skin(src image.Image, ratio int, slim bool) image.Image {
	const (
		verticalPadding   = 15
		horizontalPadding = 30
		internalPadding   = 15
	)

	r := clampRatio(ratio)
	front := newSkinRenderer(skinOptionsForAPI(r, false, -45, -25)).render(src, slim)
	back := newSkinRenderer(skinOptionsForAPI(r, false, 135, -25)).render(src, slim)

	width, height := front.w, front.h
	canvas := newGDImage((horizontalPadding+width+internalPadding)*2, verticalPadding*2+height)
	blendCopy(canvas, back, horizontalPadding, verticalPadding, 0, 0, width, height)
	blendCopy(canvas, front, horizontalPadding+width+internalPadding*2, verticalPadding, 0, 0, width, height)
	return canvas.toImage()
}

// Cape renders a cape texture with Minecraft::renderCape semantics: the cape
// front is scaled to height pixels and centred on a transparent canvas with the
// original 40x20 padding.
func Cape(src image.Image, height int) image.Image {
	const (
		verticalPadding   = 20
		horizontalPadding = 40
	)

	if height < 1 {
		height = 1
	}
	cape := renderCapeView(src, height)
	canvas := newGDImage(horizontalPadding*2+cape.w, verticalPadding*2+cape.h)
	blendCopy(canvas, cape, horizontalPadding, verticalPadding, 0, 0, cape.w, cape.h)
	return canvas.toImage()
}

// Avatar2D renders the flat, head-only 2D avatar (Minecraft::render2dAvatar).
// ratio=25 reproduces the original size used by the site.
func Avatar2D(src image.Image, ratio int) image.Image {
	return newSkinRenderer(skinOptionsForAPI(clampRatio(ratio), true, 0, 0)).render(src, false).toImage()
}

// Avatar3D renders the head-only 3D avatar (Minecraft::render3dAvatar).
// ratio=25 reproduces the original size used by the site.
func Avatar3D(src image.Image, ratio int) image.Image {
	return newSkinRenderer(skinOptionsForAPI(clampRatio(ratio), true, 45, -25)).render(src, false).toImage()
}
