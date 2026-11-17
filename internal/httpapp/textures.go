package httpapp

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/legacy/rules"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/textures"
)

func (a *App) skinlibIndex(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.render(w, r, b, "skinlib", "general.skinlib", false)
}

func (a *App) skinlibShow(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	tid, err := strconv.ParseInt(r.PathValue("texture"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	row, err := a.textures.Get(r.Context(), tid)
	if errors.Is(err, textures.ErrNotFound) {
		a.errorPage(w, r, http.StatusNotFound, "skinlib.show.deleted")
		return
	}
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !a.textures.CanView(row, b.User) {
		options, err := a.site.Options(r.Context())
		if err != nil {
			a.serverError(w, r, b)
			return
		}
		if site.Number(options["status_code_for_private"]) == http.StatusNotFound {
			a.errorPage(w, r, http.StatusNotFound, "skinlib.show.deleted")
			return
		}
		a.errorPage(w, r, http.StatusForbidden, "skinlib.show.private")
		return
	}
	available, err := a.textures.FileAvailable(row.Hash)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !available {
		a.errorPage(w, r, http.StatusNotFound, "skinlib.show.deleted")
		return
	}
	a.renderPage(w, r, b, "skinlib/show/"+strconv.FormatInt(tid, 10), row.Name, false, true)
}

func (a *App) skinlibInfo(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	tid, err := strconv.ParseInt(r.PathValue("texture"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	row, err := a.textures.Get(r.Context(), tid)
	if errors.Is(err, textures.ErrNotFound) {
		a.errorPage(w, r, http.StatusNotFound, "skinlib.show.deleted")
		return
	}
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !a.textures.CanView(row, b.User) {
		options, err := a.site.Options(r.Context())
		if err != nil {
			a.serverError(w, r, b)
			return
		}
		if site.Number(options["status_code_for_private"]) == http.StatusNotFound {
			a.abortFor(w, r, b, http.StatusNotFound, "skinlib.show.deleted")
			return
		}
		a.abortFor(w, r, b, http.StatusForbidden, "skinlib.show.private")
		return
	}
	jsonResponse(w, http.StatusOK, row)
}

// abortFor keeps the frozen HTML error page while JSON clients (the skinlib
// detail view) receive the same {"message"} shape as the original exception.
func (a *App) abortFor(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, status int, key string) {
	if wantsJSON(r) {
		failure(w, status, a.message(r, b, key))
		return
	}
	a.errorPage(w, r, status, key)
}

func (a *App) skinlibList(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	query := r.URL.Query()
	page := 1
	if parsed, err := strconv.Atoi(query.Get("page")); err == nil {
		page = parsed
	}
	uploader, _ := strconv.ParseInt(query.Get("uploader"), 10, 64)
	params := textures.LibraryParams{
		Filter:   query.Get("filter"),
		Keyword:  query.Get("keyword"),
		Uploader: uploader,
		Sort:     query.Get("sort"),
		Page:     page,
	}
	values := url.Values{}
	for _, key := range []string{"filter", "keyword", "uploader", "sort"} {
		if value := query.Get(key); value != "" {
			values.Set(key, value)
		}
	}
	base := a.cfg.BaseURL + strings.TrimPrefix(r.URL.Path, a.basePath)
	if encoded := values.Encode(); encoded != "" {
		base += "?" + encoded + "&page="
	} else {
		base += "?page="
	}
	value, err := a.textures.Library(r.Context(), b.User, params, a.cfg.BaseURL+strings.TrimPrefix(r.URL.Path, a.basePath), base)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, http.StatusOK, value)
}

func (a *App) skinlibUploadPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !a.requireVerified(w, r, b, options) {
		return
	}
	a.render(w, r, b, "skinlib/upload", "skinlib.upload.title", false)
}

func (a *App) textureUpload(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !a.requireVerified(w, r, b, options) {
		return
	}
	maxBytes := site.Number(options["max_upload_file_size"]) * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes+1<<20)
	if err = r.ParseMultipartForm(maxBytes + 1<<20); err != nil {
		validation(w, map[string][]string{"file": {a.fieldMessage(r, b, "file", "max.file", ":max", strconv.FormatInt(maxBytes/1024, 10))}})
		return
	}
	if !a.csrf(w, r, b, input{}) {
		return
	}
	fields := map[string][]string{}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		fields["name"] = []string{a.fieldMessage(r, b, "name", "required")}
	} else {
		pattern, _ := options["texture_name_regexp"].(string)
		matched, err := rules.MatchTexture(pattern, name)
		if err != nil {
			a.serverError(w, r, b)
			return
		}
		if !matched {
			fields["name"] = []string{a.fieldMessage(r, b, "name", "regex")}
		}
	}
	kind := r.FormValue("type")
	if kind != "steve" && kind != "alex" && kind != "cape" {
		fields["type"] = []string{a.fieldMessage(r, b, "type", "in")}
	}
	publicValue, publicPresent := r.Form["public"]
	public, ok := false, false
	if publicPresent && len(publicValue) > 0 {
		public, ok = parsePublic(publicValue[0])
	}
	if !publicPresent {
		fields["public"] = []string{a.fieldMessage(r, b, "public", "required")}
	} else if !ok {
		fields["public"] = []string{a.fieldMessage(r, b, "public", "boolean")}
	}
	file, header, fileErr := r.FormFile("file")
	if fileErr != nil {
		fields["file"] = []string{a.fieldMessage(r, b, "file", "required")}
	} else {
		defer file.Close()
	}
	if len(fields) > 0 {
		validation(w, fields)
		return
	}
	if header.Size > maxBytes {
		validation(w, map[string][]string{"file": {a.fieldMessage(r, b, "file", "max.file", ":max", strconv.FormatInt(maxBytes/1024, 10))}})
		return
	}
	source, written, err := a.textures.StageUpload(file, maxBytes)
	if errors.Is(err, textures.ErrTooLarge) {
		validation(w, map[string][]string{"file": {a.fieldMessage(r, b, "file", "max.file", ":max", strconv.FormatInt(maxBytes/1024, 10))}})
		return
	}
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	defer os.Remove(source)
	tid, err := a.textures.Upload(r.Context(), textures.UploadInput{Browser: b, Name: name, Type: kind, Public: public, Source: source, Bytes: written})
	var duplicate *textures.DuplicateError
	var dimensions *textures.DimensionError
	switch {
	case errors.As(err, &dimensions):
		a.business(w, r, b, 1, "skinlib.upload.invalid-size", ":type", a.textureTypeLabel(r, b, kind), ":width", strconv.Itoa(dimensions.Width), ":height", strconv.Itoa(dimensions.Height))
		return
	case errors.Is(err, textures.ErrNotPNG):
		validation(w, map[string][]string{"file": {a.fieldMessage(r, b, "file", "mimes", ":values", "png")}})
		return
	case errors.As(err, &duplicate):
		jsonResponse(w, http.StatusOK, map[string]any{"code": 2, "message": a.message(r, b, "skinlib.upload.repeated"), "data": map[string]int64{"tid": duplicate.TID}})
		return
	case errors.Is(err, textures.ErrTooLarge):
		validation(w, map[string][]string{"file": {a.fieldMessage(r, b, "file", "max.file", ":max", strconv.FormatInt(maxBytes/1024, 10))}})
		return
	case errors.Is(err, textures.ErrLackScore):
		a.business(w, r, b, 1, "skinlib.upload.lack-score")
		return

	case errors.Is(err, textures.ErrInvalidName):
		validation(w, map[string][]string{"name": {a.fieldMessage(r, b, "name", "required")}})
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": a.message(r, b, "skinlib.upload.success", ":name", name), "data": map[string]int64{"tid": tid}})
}

func parsePublic(raw string) (bool, bool) {
	switch raw {
	case "1":
		return true, true
	case "0":
		return false, true
	}
	return false, false
}

func (a *App) textureTypeLabel(r *http.Request, b *identity.BrowserSession, kind string) string {
	if kind == "cape" {
		return a.message(r, b, "general.cape")
	}
	return a.message(r, b, "general.skin")
}
