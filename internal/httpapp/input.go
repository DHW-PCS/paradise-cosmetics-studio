package httpapp

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// input preserves missing, null, empty and typed JSON values until validation.
type input map[string]any

func decode(r *http.Request) (input, error) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil && r.Header.Get("Content-Type") != "" {
		return nil, err
	}
	if media == "application/json" {
		var values input
		d := json.NewDecoder(r.Body)
		d.UseNumber()
		if err = d.Decode(&values); err == io.EOF {
			return input{}, nil
		} else if err != nil {
			return nil, err
		}
		if values == nil {
			return nil, errors.New("expected JSON object")
		}
		if err = d.Decode(new(any)); err != io.EOF {
			return nil, errors.New("expected one JSON object")
		}
		for key, value := range values {
			if text, ok := value.(string); ok && key != "password" && key != "password_confirmation" {
				text = strings.Trim(text, " \t\n\r\x00\x0b")
				if text == "" {
					values[key] = nil
				} else {
					values[key] = text
				}
			}
		}
		return values, nil
	}
	if media == "multipart/form-data" {
		err = r.ParseMultipartForm(32 << 20)
	} else {
		err = r.ParseForm()
	}
	if err != nil {
		return nil, err
	}
	// net/http parses URL-encoded bodies for POST/PUT/PATCH; legacy DELETE
	// forms also carry body parameters and override query values.
	if media == "application/x-www-form-urlencoded" && r.Method == http.MethodDelete {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		fields, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		for key, values := range fields {
			r.Form[key] = values
		}
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	values := input{}
	for key, texts := range r.Form {
		text := texts[len(texts)-1]
		if key != "password" && key != "password_confirmation" {
			text = strings.Trim(text, " \t\n\r\x00\x0b")
		}
		if text == "" {
			values[key] = nil
		} else {
			values[key] = text
		}
	}
	return values, nil
}
func (v input) text(key string) string { s, _ := v[key].(string); return s }

// truth follows the untyped remember argument accepted by the original guard.
func (v input) truth(key string) bool {
	switch value := v[key].(type) {
	case nil:
		return false
	case bool:
		return value
	case string:
		return value != "" && value != "0"
	case json.Number:
		number, _ := strconv.ParseFloat(string(value), 64)
		return number != 0
	case []any:
		return len(value) != 0
	case map[string]any:
		return len(value) != 0
	}
	panic("unsupported decoded input value")
}
