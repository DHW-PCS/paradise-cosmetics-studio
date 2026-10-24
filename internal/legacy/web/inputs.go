package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type inputCache struct {
	form url.Values
	json map[string]any
	err  error
	done bool
}

var inputKey = contextKey{"inputs"}

func inputs(r *http.Request) *inputCache {
	if cached, ok := r.Context().Value(inputKey).(*inputCache); ok {
		return cached
	}
	cache := &inputCache{}
	return cache
}

// withInputs stores the parsed request inputs so the CSRF middleware and the
// handler do not consume the body twice.
func withInputs(r *http.Request, cache *inputCache) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), inputKey, cache))
}

func (c *inputCache) load(r *http.Request) {
	if c.done {
		return
	}
	c.done = true
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(strings.ToLower(contentType), "json") {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			c.err = err
			return
		}
		if len(strings.TrimSpace(string(body))) == 0 {
			c.json = map[string]any{}
			return
		}
		var decoded map[string]any
		if err := json.Unmarshal(body, &decoded); err != nil {
			c.err = err
			return
		}
		c.json = decoded
		return
	}
	if err := r.ParseForm(); err != nil {
		c.err = err
		return
	}
	c.form = r.Form
}

// inputString returns a trimmed scalar input, mirroring TrimStrings and
// ConvertEmptyStringsToNull. The password is trimmed by the frozen 8.75 stack
// as well because its $except list is empty.
func inputString(r *http.Request, name string) string {
	cache := inputs(r)
	cache.load(r)
	if cache.err != nil {
		return ""
	}
	if cache.json != nil {
		switch value := cache.json[name].(type) {
		case string:
			return strings.TrimSpace(value)
		case nil:
			return ""
		default:
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	if cache.form == nil {
		return ""
	}
	return strings.TrimSpace(cache.form.Get(name))
}

// inputTruthy follows PHP truthiness for the keep flag.
func inputTruthy(r *http.Request, name string) bool {
	cache := inputs(r)
	cache.load(r)
	if cache.err != nil {
		return false
	}
	var value any
	if cache.json != nil {
		value = cache.json[name]
	} else if cache.form != nil {
		values, ok := cache.form[name]
		if !ok {
			return false
		}
		value = values[0]
	}
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		return v != "" && v != "0"
	default:
		return true
	}
}
