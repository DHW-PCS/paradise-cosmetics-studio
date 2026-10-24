// Package media contains bounded PNG validation and the M1 game-upload slice.
package media

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
)

var ErrDenied = errors.New("media: invalid PNG, model, ownership or insufficient score")

const MaxBytes = 16 << 20
const MaxPixels = 16 << 20

type PNG struct {
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Bytes  int    `json:"bytes"`
	KiB    int    `json:"kib"`
	Hash   string `json:"hash"`
}

func Inspect(data []byte, kind string) (PNG, error) {
	var out PNG
	if len(data) == 0 || len(data) > MaxBytes {
		return out, ErrDenied
	}
	c, e := png.DecodeConfig(bytes.NewReader(data))
	if e != nil || c.Width <= 0 || c.Height <= 0 || int64(c.Width)*int64(c.Height) > MaxPixels {
		return out, ErrDenied
	}
	// The legacy game cape path checks only its 2:1 ratio. Skin paths retain
	// their 64/32 constraints, including legal HD and 64x32 Steve inputs.
	switch kind {
	case "steve":
		if c.Width%64 != 0 || c.Height%32 != 0 || (c.Width != c.Height && c.Width != 2*c.Height) {
			return out, ErrDenied
		}
	case "alex":
		if c.Width%64 != 0 || c.Width != c.Height {
			return out, ErrDenied
		}
	case "cape":
		if c.Width != 2*c.Height {
			return out, ErrDenied
		}
	default:
		return out, ErrDenied
	}
	if _, e = png.Decode(bytes.NewReader(data)); e != nil {
		return out, ErrDenied
	}
	h := sha256.Sum256(data)
	return PNG{c.Width, c.Height, len(data), (len(data) + 1023) / 1024, hex.EncodeToString(h[:])}, nil
}

// Multipart reads the standard PUT wire format without altering binary CRLF.
func Multipart(r *http.Request) ([]byte, string, string, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, MaxBytes+(1<<20))
	reader, e := r.MultipartReader()
	if e != nil {
		return nil, "", "", ErrDenied
	}
	var data []byte
	var model, name string
	seen := map[string]bool{}
	for {
		p, e := reader.NextPart()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, "", "", ErrDenied
		}
		field := p.FormName()
		if seen[field] || (field != "file" && field != "model") {
			p.Close()
			return nil, "", "", ErrDenied
		}
		seen[field] = true
		switch field {
		case "file":
			if p.FileName() == "" {
				return nil, "", "", ErrDenied
			}
			name = p.FileName()
			data, e = readPart(p, MaxBytes)
		case "model":
			var b []byte
			b, e = readPart(p, 32)
			model = string(b)
		}
		p.Close()
		if e != nil {
			return nil, "", "", ErrDenied
		}
	}
	if len(data) == 0 || (model != "" && model != "slim" && model != "default") {
		return nil, "", "", ErrDenied
	}
	return data, model, name, nil
}
func readPart(p *multipart.Part, n int64) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(p, n+1))
	if e != nil || int64(len(b)) > n {
		return nil, ErrDenied
	}
	return b, nil
}

// Avatar is a native bounded 2D face/hat prototype. Exact GD polygon and
// resampling equivalence is evaluated separately; full previews use a bridge.
func Avatar(data []byte, size int) (image.Image, error) {
	if size < 1 || size > 1024 {
		return nil, ErrDenied
	}
	meta, e := Inspect(data, "steve")
	if e != nil {
		return nil, e
	}
	src, e := png.Decode(bytes.NewReader(data))
	if e != nil {
		return nil, e
	}
	scale := meta.Width / 64
	face := image.NewNRGBA(image.Rect(0, 0, 8*scale, 8*scale))
	draw.Draw(face, face.Bounds(), src, image.Pt(8*scale, 8*scale), draw.Src)
	draw.Draw(face, face.Bounds(), src, image.Pt(40*scale, 8*scale), draw.Over)
	out := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			out.Set(x, y, color.NRGBAModel.Convert(face.At(x*face.Bounds().Dx()/size, y*face.Bounds().Dy()/size)))
		}
	}
	return out, nil
}
