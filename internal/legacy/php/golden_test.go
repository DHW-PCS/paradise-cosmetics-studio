package php

import "testing"

// Produced by the frozen PHP 8.1 build:
// serialize(["_token" => "...", "login_web_x" => 1, "_flash" => ["old" => [], "new" => ["k" => "v"]], "unicode" => "中文"])
const goldenSessionPayload = `a:4:{s:6:"_token";s:40:"0123456789012345678901234567890123456789";s:11:"login_web_x";i:1;s:6:"_flash";a:2:{s:3:"old";a:0:{}s:3:"new";a:1:{s:1:"k";s:1:"v";}}s:7:"unicode";s:6:"中文";}`

func TestGoldenSessionPayloadRoundTrip(t *testing.T) {
	v, err := Unmarshal([]byte(goldenSessionPayload))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	attrs, ok := v.(*Array)
	if !ok {
		t.Fatalf("payload type = %T", v)
	}
	if uid, ok := attrs.GetInt("login_web_x"); !ok || uid != 1 {
		t.Fatalf("login_web_x = %d, %v", uid, ok)
	}
	if token, ok := attrs.GetString("_token"); !ok || token != "0123456789012345678901234567890123456789" {
		t.Fatalf("_token = %q", token)
	}
	if value, ok := attrs.GetPath("_flash.new.k"); !ok || value != "v" {
		t.Fatalf("_flash.new.k = %#v", value)
	}
	if value, ok := attrs.GetPath("unicode"); !ok || value != "中文" {
		t.Fatalf("unicode = %#v", value)
	}
	out, err := Marshal(attrs)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != goldenSessionPayload {
		t.Fatalf("round trip changed bytes:\n got %q\nwant %q", out, goldenSessionPayload)
	}
}
