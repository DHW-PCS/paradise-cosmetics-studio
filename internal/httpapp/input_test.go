package httpapp

import (
	"bytes"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInputShapes(t *testing.T) {
	for _, test := range []struct{ method, media, body string }{
		{"POST", "application/json; charset=utf-8", `{"name":"  中文  ","password":" raw ","empty":"","password_confirmation":"  ","zero":0,"keep":false}`},
		{"DELETE", "application/x-www-form-urlencoded", "name=++%E4%B8%AD%E6%96%87++&password=+raw+&password_confirmation=++&empty=&zero=0&keep=0"},
	} {
		r := httptest.NewRequest(test.method, "http://localhost/?query=kept", strings.NewReader(test.body))
		r.Header.Set("Content-Type", test.media)
		v, err := decode(r)
		if err != nil {
			t.Fatal(err)
		}
		keep := v.truth("keep")
		if v.text("name") != "中文" || v.text("password") != "raw" || v["empty"] != nil || v["password_confirmation"] != nil || v["missing"] != nil || keep {
			t.Fatal("input coercion changed")
		}
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("name", "one")
	_ = writer.WriteField("name", "two")
	_ = writer.Close()
	r := httptest.NewRequest("PUT", "http://localhost/", &body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	v, err := decode(r)
	if err != nil || v.text("name") != "two" {
		t.Fatal("multipart/repeated value handling changed")
	}
	r = httptest.NewRequest("POST", "http://localhost/", strings.NewReader(`{"name":"\u00a0中文\u00a0","keep":"false"}`))
	r.Header.Set("Content-Type", "application/json")
	v, err = decode(r)
	if err != nil || v.text("name") != "\u00a0中文\u00a0" || !v.truth("keep") {
		t.Fatal("PHP trim or remember truthiness changed")
	}
}
