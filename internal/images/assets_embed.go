package images

import "embed"

//go:embed assets/*.png
var embeddedAssets embed.FS
