package media

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image/png"
	"os/exec"
	"time"
)

// Renderer is a read-only, bounded process bridge to the frozen GD renderer.
// Only trusted deployment configuration supplies Executable and Script.
// It has no credential writer and must be removed after native visual parity.
type Renderer struct{ Executable, Script string }

func (r Renderer) Render(ctx context.Context, data []byte, kind, mode string, height int) ([]byte, error) {
	if _, e := Inspect(data, kind); e != nil {
		return nil, e
	}
	if mode != "preview" && mode != "2d" && mode != "3d" {
		return nil, ErrDenied
	}
	if height < 1 || height > 1024 {
		return nil, ErrDenied
	}
	request, _ := json.Marshal(map[string]any{"png": base64.StdEncoding.EncodeToString(data), "kind": kind, "mode": mode, "height": height})
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.Executable, r.Script)
	cmd.Stdin = bytes.NewReader(request)
	var out cappedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &cappedBuffer{}
	if e := cmd.Run(); e != nil {
		return nil, errors.New("media: renderer process failed")
	}
	var result struct {
		PNG string `json:"png"`
	}
	if json.Unmarshal(out.Bytes(), &result) != nil {
		return nil, ErrDenied
	}
	b, e := base64.StdEncoding.DecodeString(result.PNG)
	if e != nil || len(b) > MaxBytes {
		return nil, ErrDenied
	}
	c, e := png.DecodeConfig(bytes.NewReader(b))
	if e != nil || c.Width > 8192 || c.Height > 8192 || int64(c.Width)*int64(c.Height) > MaxPixels {
		return nil, ErrDenied
	}
	return b, nil
}

type cappedBuffer struct{ bytes.Buffer }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 24<<20 {
		return 0, ErrDenied
	}
	return b.Buffer.Write(p)
}
