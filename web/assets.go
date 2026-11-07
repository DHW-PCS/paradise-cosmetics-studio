// Package web embeds templates and the reproducibly built frontend.
package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"strings"
)

//go:embed templates all:static
var files embed.FS

type Assets struct {
	Static    fs.FS
	Manifest  map[string][]string
	Templates *template.Template
	Messages  map[string]map[string]any
	// ReadmeYggdrasilAPI is the frozen yggdrasil-api README.md rendered by
	// the admin readme page; the original read the plugin directory at
	// runtime, the Go replacement ships the same bytes as a static asset.
	ReadmeYggdrasilAPI []byte
}

func Load() (*Assets, error) {
	static, _ := fs.Sub(files, "static")
	b, err := fs.ReadFile(static, "app/manifest.json")
	if err != nil {
		return nil, fmt.Errorf("frontend assets missing: run make frontend before building")
	}
	a := &Assets{Static: static, Messages: map[string]map[string]any{}}
	if err = json.Unmarshal(b, &a.Manifest); err != nil {
		return nil, err
	}
	a.Templates, err = template.New("pages").ParseFS(files, "templates/*.gohtml")
	if err != nil {
		return nil, err
	}
	a.ReadmeYggdrasilAPI, err = fs.ReadFile(files, "templates/yggdrasil_readme.md")
	if err != nil {
		return nil, err
	}
	paths, err := fs.Glob(static, "lang/*.json")
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		b, err = fs.ReadFile(static, path)
		if err != nil {
			return nil, err
		}
		var messages map[string]any
		if err = json.Unmarshal(b, &messages); err != nil {
			return nil, err
		}
		a.Messages[strings.TrimSuffix(strings.TrimPrefix(path, "lang/"), ".json")] = messages
	}
	return a, nil
}
