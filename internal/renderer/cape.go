package renderer

import "image"

// renderCapeView mirrors Blessing\Renderer\CapeRenderer::render.
func renderCapeView(src image.Image, height int) *gdImage {
	resource := fromImage(src)

	srcWidth := resource.w
	srcHeight := resource.h
	hdRatio := float64(srcWidth) / 64
	outHeight := height
	outWidth := int(float64(outHeight) / 16 * 10)
	if outWidth < 1 {
		outWidth = 1
	}

	canvas := newGDImage(outWidth, outHeight)
	resample(
		canvas, resource,
		0, 0, int(1*hdRatio), int(1*hdRatio),
		outWidth, outHeight,
		int(float64(srcWidth)*10/64), int(float64(srcHeight)*16/32),
	)
	return canvas
}
