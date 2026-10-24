package media

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http/httptest"
	"testing"
)

func TestBinaryPUTMultipartPreservesCRLFAndRejectsDuplicate(t *testing.T) {
	data := []byte{0, 255, 13, 10, 0, 1, 13, 10, 255}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("file", "skin.png")
	part.Write(data)
	writer.WriteField("model", "slim")
	writer.Close()
	req := httptest.NewRequest("PUT", "/profile/skin", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	got, model, _, e := Multipart(req)
	if e != nil || !bytes.Equal(got, data) || model != "slim" {
		t.Fatalf("binary changed: %v %v", got, e)
	}
	body.Reset()
	writer = multipart.NewWriter(&body)
	for range 2 {
		part, _ = writer.CreateFormFile("file", "skin.png")
		part.Write(data)
	}
	writer.Close()
	req = httptest.NewRequest("PUT", "/profile/skin", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if _, _, _, e = Multipart(req); e == nil {
		t.Fatal("duplicate file accepted")
	}
}
func TestPNGModelsAndResourceLimits(t *testing.T) {
	for _, tc := range []struct {
		w, h  int
		kind  string
		valid bool
	}{{64, 32, "steve", true}, {64, 32, "alex", false}, {128, 128, "alex", true}, {22, 11, "cape", true}, {22, 11, "steve", false}, {64, 64, "cape", false}} {
		var b bytes.Buffer
		im := image.NewNRGBA(image.Rect(0, 0, tc.w, tc.h))
		im.Set(1, 1, color.NRGBA{255, 128, 0, 128})
		png.Encode(&b, im)
		meta, e := Inspect(b.Bytes(), tc.kind)
		if (e == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc, e)
		}
		if e == nil && (meta.KiB != (b.Len()+1023)/1024 || meta.Bytes != b.Len()) {
			t.Fatal("billing units")
		}
	}
	if _, e := Inspect([]byte("not png"), "steve"); e == nil {
		t.Fatal("non PNG accepted")
	}
}
