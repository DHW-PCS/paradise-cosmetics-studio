// Package buildcompat prototypes Twig conversion and PHP-free build outputs.
package buildcompat

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

//go:embed templates/codes.gohtml
var codes string

type Code struct {
	Code, GeneratedAt, UsedAt string
	UsedBy                    int64
}
type CodesPage struct {
	Free, Used               []Code
	GenerateURL, CSRF, Error string
}

func RenderCodes(p CodesPage, translate func(string) string) (string, error) {
	t, e := template.New("codes").Funcs(template.FuncMap{"trans": translate}).Parse(codes)
	if e != nil {
		return "", e
	}
	var out bytes.Buffer
	e = t.Execute(&out, p)
	return out.String(), e
}

// Extra uses html/template's JSON encoder in a script context: U+2028,
// U+2029 and </script> cannot break out of the inline JSON element.
func Extra(v any) (string, error) {
	t, e := template.New("extra").Parse(`<script id="blessing-extra" type="application/json">{{.}}</script>`)
	if e != nil {
		return "", e
	}
	var b bytes.Buffer
	e = t.Execute(&b, v)
	return b.String(), e
}

type Entry struct {
	Name   string   `json:"name"`
	Assets []string `json:"assets"`
}

// Fragments consumes a webpack entrypoint manifest. It preserves emitted
// dependency order instead of independently sorting JS chunks.
func Fragments(entries []Entry, base string) (map[string]string, error) {
	out := map[string]string{}
	u, e := url.Parse(base)
	if e != nil || (u.Scheme != "" && u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("build: invalid CDN base")
	}
	for _, entry := range entries {
		if entry.Name == "" {
			return nil, errors.New("build: empty entry")
		}
		if _, ok := out[entry.Name]; ok {
			return nil, errors.New("build: duplicate entry")
		}
		var b strings.Builder
		seen := map[string]bool{}
		for _, asset := range entry.Assets {
			if asset == "" || strings.ContainsAny(asset, "?#\\") || path.IsAbs(asset) || strings.Contains(asset, "..") || seen[asset] {
				return nil, errors.New("build: invalid asset")
			}
			seen[asset] = true
			address := strings.TrimRight(base, "/") + "/app/" + asset
			switch path.Ext(asset) {
			case ".js":
				fmt.Fprintf(&b, `<script src="%s" crossorigin="anonymous"></script>`, template.HTMLEscapeString(address))
			case ".css":
				fmt.Fprintf(&b, `<link href="%s" rel="stylesheet" crossorigin="anonymous">`, template.HTMLEscapeString(address))
			default:
				return nil, errors.New("build: unsupported asset")
			}
		}
		out[entry.Name] = b.String()
	}
	return out, nil
}

// Routes supplies the nested function-call shape consumed by urls.ts. Param
// substitutions use encodeURIComponent, matching JavaScript URL semantics.
func Routes(routes map[string]string) (string, error) {
	keys := make([]string, 0, len(routes))
	for k := range routes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tree := map[string]any{}
	for _, k := range keys {
		parts := strings.Split(k, ".")
		node := tree
		for i, p := range parts {
			if p == "" || p == "__proto__" || p == "constructor" || p == "prototype" {
				return "", errors.New("build: invalid route name")
			}
			if i == len(parts)-1 {
				if _, ok := node[p]; ok {
					return "", errors.New("build: duplicate route")
				}
				node[p] = routes[k]
			} else {
				if next, ok := node[p]; ok {
					m, ok := next.(map[string]any)
					if !ok {
						return "", errors.New("build: route collision")
					}
					node = m
				} else {
					m := map[string]any{}
					node[p] = m
					node = m
				}
			}
		}
	}
	var emit func(map[string]any) string
	emit = func(m map[string]any) string {
		ks := make([]string, 0, len(m))
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		var b strings.Builder
		b.WriteString("{")
		for _, k := range ks {
			key, _ := json.Marshal(k)
			b.Write(key)
			b.WriteString(":")
			switch v := m[k].(type) {
			case map[string]any:
				b.WriteString(emit(v))
			case string:
				raw, _ := json.Marshal(v)
				matches := regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`).FindAllStringSubmatch(v, -1)
				names := []string{}
				seen := map[string]bool{}
				for _, m := range matches {
					if !seen[m[1]] {
						names = append(names, m[1])
						seen[m[1]] = true
					}
				}
				params, _ := json.Marshal(names)
				b.WriteString("(...args) => { const names = ")
				b.Write(params)
				b.WriteString("; return ")
				b.Write(raw)
				b.WriteString(`.replace(/\{([A-Za-z0-9_]+)\}/g, (_, key) => { const i = names.indexOf(key); if (i < 0 || args[i] === undefined) throw new Error('missing route parameter'); return encodeURIComponent(String(args[i])); }); }`)
			}
			b.WriteString(",")
		}
		b.WriteString("}")
		return b.String()
	}
	return "export default " + emit(tree) + ";\n", nil
}
