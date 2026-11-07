package httpapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"blessing-skin-go/internal/modules"
	"blessing-skin-go/internal/players"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/textures"
	"blessing-skin-go/internal/yggdrasil"
)

// yggdrasilModule is the fixed module name served by this dispatcher.
const yggdrasilModule = "yggdrasil-api"

// yggNotFound renders the module-absent protocol 404: a disabled or
// unregistered module behaves like an unregistered route.
func (a *App) yggNotFound(w http.ResponseWriter) {
	jsonResponse(w, http.StatusNotFound, map[string]string{
		"error":        "NotFoundException",
		"errorMessage": "Not Found.",
	})
}

// yggGate reports whether the module is installed and enabled on one
// consistent statement. Business transactions re-check the same facts
// under the shared lock inside the service; this gate only shapes the
// module-absent answer before any business work starts.
func (a *App) yggGate(w http.ResponseWriter, r *http.Request) bool {
	served, err := a.servedModule(r.Context(), yggdrasilModule)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{
			"error":        "InternalServerError",
			"errorMessage": "Internal Server Error.",
		})
		return false
	}
	if !served || a.ygg == nil {
		a.yggNotFound(w)
		return false
	}
	return true
}

// yggModuleLockFunc installs the module-state shared current read inside
// a business transaction and refuses with ErrModuleNotServed when the
// module is unregistered or disabled at commit time.
func (a *App) yggModuleLockFunc() func(context.Context, *sql.Tx) error {
	return func(ctx context.Context, tx *sql.Tx) error {
		state, err := a.modules.LockStateTx(ctx, tx)
		if err != nil {
			return err
		}
		if !state.HasInstalled(yggdrasilModule) || !state.HasEnabled(yggdrasilModule) {
			return yggdrasil.ErrModuleNotServed
		}
		return nil
	}
}

// stateHasEnabled reports an enable entry by object name or legacy
// string entry, matching the original plugin enable list shape.
func stateHasEnabled(state *modules.State, name string) bool {
	for _, entry := range state.Enabled {
		if entry.Name == name || entry.Legacy == name {
			return true
		}
	}
	return false
}

// yggError renders a service error in the frozen protocol shape. Protocol
// APIErrors keep their status, name and message; anything else is a
// generic 500 without internal detail.
func (a *App) yggError(w http.ResponseWriter, err error) {
	if errors.Is(err, yggdrasil.ErrModuleNotServed) {
		a.yggNotFound(w)
		return
	}
	if apiErr, ok := err.(*yggdrasil.APIError); ok {
		body := map[string]string{"error": apiErr.Name, "errorMessage": apiErr.Message}
		if apiErr.Cause != "" {
			body["cause"] = apiErr.Cause
		}
		jsonResponse(w, apiErr.Status, body)
		return
	}
	jsonResponse(w, http.StatusInternalServerError, map[string]string{
		"error":        "InternalServerError",
		"errorMessage": "Internal Server Error.",
	})
}

// yggCheckContentType mirrors the legacy CheckContentType middleware: a
// non-JSON request answers with the error object at the default 200
// status, never 415.
func (a *App) yggCheckContentType(w http.ResponseWriter, r *http.Request) bool {
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "json") {
		return true
	}
	jsonResponse(w, http.StatusOK, map[string]string{
		"error":        "Unsupported Media Type",
		"errorMessage": `"Content-Type" must be "application/json".`,
	})
	return false
}

// readYggJSON reads the request body once. Handlers decode the returned
// bytes into both the raw map (legacy input semantics) and a typed
// struct (field presence), so the body is never consumed twice.
func readYggJSON(r *http.Request) []byte {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	return body
}

// decodeYggJSON decodes leniently: an empty or malformed body yields the
// zero value, matching legacy $request->input nulls.
func decodeYggJSON(body []byte, value any) {
	if len(strings.TrimSpace(string(body))) == 0 {
		return
	}
	_ = json.Unmarshal(body, value)
}

// phpJSONTruthy mirrors PHP truthiness for a decoded JSON value.
func phpJSONTruthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != "" && v != "0"
	case json.Number:
		number, _ := v.Float64()
		return number != 0
	case float64:
		return v != 0
	case []any:
		return len(v) != 0
	case map[string]any:
		return len(v) != 0
	}
	return false
}

// yggRequestUser reports the legacy requestUser flag from raw JSON.
func yggRequestUser(raw map[string]any) bool {
	return phpJSONTruthy(raw["requestUser"])
}

type yggAuthResponse struct {
	AccessToken       string              `json:"accessToken"`
	ClientToken       string              `json:"clientToken"`
	AvailableProfiles []yggdrasil.Profile `json:"availableProfiles"`
	User              *yggdrasil.User     `json:"user,omitempty"`
	SelectedProfile   *yggdrasil.Profile  `json:"selectedProfile,omitempty"`
}

func yggAuthJSON(res *yggdrasil.AuthenticateResult, refresh *yggdrasil.RefreshResult, requestUser bool) yggAuthResponse {
	out := yggAuthResponse{}
	if res != nil {
		out.AccessToken = res.AccessToken
		out.ClientToken = res.ClientToken
		out.AvailableProfiles = res.AvailableProfiles
		out.SelectedProfile = res.SelectedProfile
		if requestUser {
			out.User = res.User
		}
	}
	if refresh != nil {
		out.AccessToken = refresh.AccessToken
		out.ClientToken = refresh.ClientToken
		out.AvailableProfiles = refresh.AvailableProfiles
		out.SelectedProfile = refresh.SelectedProfile
		if requestUser {
			out.User = refresh.User
		}
	}
	if out.AvailableProfiles == nil {
		out.AvailableProfiles = []yggdrasil.Profile{}
	}
	return out
}

func (a *App) yggAuthenticate(w http.ResponseWriter, r *http.Request) {
	if !a.yggGate(w, r) {
		return
	}
	if !a.yggCheckContentType(w, r) {
		return
	}
	bodyBytes := readYggJSON(r)
	var raw map[string]any
	decodeYggJSON(bodyBytes, &raw)
	var creds struct {
		Username    string  `json:"username"`
		Password    string  `json:"password"`
		ClientToken *string `json:"clientToken"`
	}
	decodeYggJSON(bodyBytes, &creds)
	res, err := a.ygg.Authenticate(r.Context(), yggdrasil.AuthenticateRequest{
		Username: creds.Username, Password: creds.Password,
		ClientToken: creds.ClientToken, RequestUser: yggRequestUser(raw), ClientIP: clientIP(r),
	})
	if err != nil {
		a.yggError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, yggAuthJSON(res, nil, yggRequestUser(raw)))
}

func (a *App) yggRefresh(w http.ResponseWriter, r *http.Request) {
	if !a.yggGate(w, r) {
		return
	}
	if !a.yggCheckContentType(w, r) {
		return
	}
	bodyBytes := readYggJSON(r)
	var raw map[string]any
	decodeYggJSON(bodyBytes, &raw)
	var body struct {
		AccessToken     string                          `json:"accessToken"`
		ClientToken     *string                         `json:"clientToken"`
		SelectedProfile *yggdrasil.SelectedProfileInput `json:"selectedProfile"`
	}
	decodeYggJSON(bodyBytes, &body)
	res, err := a.ygg.Refresh(r.Context(), yggdrasil.RefreshRequest{
		AccessToken: body.AccessToken, ClientToken: body.ClientToken,
		SelectedProfile: body.SelectedProfile, ClientIP: clientIP(r),
	})
	if err != nil {
		a.yggError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, yggAuthJSON(nil, res, yggRequestUser(raw)))
}

func (a *App) yggValidate(w http.ResponseWriter, r *http.Request) {
	if !a.yggGate(w, r) {
		return
	}
	if !a.yggCheckContentType(w, r) {
		return
	}
	var body struct {
		AccessToken string  `json:"accessToken"`
		ClientToken *string `json:"clientToken"`
	}
	decodeYggJSON(readYggJSON(r), &body)
	if err := a.ygg.Validate(r.Context(), yggdrasil.ValidateRequest{
		AccessToken: body.AccessToken, ClientToken: body.ClientToken, ClientIP: clientIP(r),
	}); err != nil {
		a.yggError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) yggInvalidate(w http.ResponseWriter, r *http.Request) {
	if !a.yggGate(w, r) {
		return
	}
	if !a.yggCheckContentType(w, r) {
		return
	}
	var body struct {
		AccessToken string `json:"accessToken"`
	}
	decodeYggJSON(readYggJSON(r), &body)
	if err := a.ygg.Invalidate(r.Context(), yggdrasil.InvalidateRequest{
		AccessToken: body.AccessToken, ClientIP: clientIP(r),
	}); err != nil {
		a.yggError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) yggSignout(w http.ResponseWriter, r *http.Request) {
	if !a.yggGate(w, r) {
		return
	}
	if !a.yggCheckContentType(w, r) {
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	decodeYggJSON(readYggJSON(r), &body)
	if err := a.ygg.Signout(r.Context(), yggdrasil.SignoutRequest{
		Username: body.Username, Password: body.Password, ClientIP: clientIP(r),
	}); err != nil {
		a.yggError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) yggJoin(w http.ResponseWriter, r *http.Request) {
	if !a.yggGate(w, r) {
		return
	}
	var body struct {
		AccessToken     string `json:"accessToken"`
		SelectedProfile string `json:"selectedProfile"`
		ServerID        string `json:"serverId"`
	}
	decodeYggJSON(readYggJSON(r), &body)
	if err := a.ygg.JoinServer(r.Context(), yggdrasil.JoinServerRequest{
		AccessToken: body.AccessToken, SelectedProfile: body.SelectedProfile,
		ServerID: body.ServerID, ClientIP: clientIP(r),
	}); err != nil {
		a.yggError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) yggHasJoined(w http.ResponseWriter, r *http.Request) {
	if !a.yggGate(w, r) {
		return
	}
	query := r.URL.Query()
	req := yggdrasil.HasJoinedServerRequest{
		Username: query.Get("username"), ServerID: query.Get("serverId"),
	}
	if _, present := query["ip"]; present {
		value := query.Get("ip")
		req.IP = &value
	}
	doc, found, err := a.ygg.HasJoinedServer(r.Context(), req)
	if err != nil {
		a.yggError(w, err)
		return
	}
	if !found {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(doc.JSON))
}

func (a *App) yggProfile(w http.ResponseWriter, r *http.Request) {
	if !a.yggGate(w, r) {
		return
	}
	// Strict string semantics: only the exact value "false" signs; a
	// missing or any other value stays unsigned.
	signed := r.URL.Query().Get("unsigned") == "false"
	doc, found, err := a.ygg.GetProfileByUUID(r.Context(), r.PathValue("uuid"), signed)
	if err != nil {
		a.yggError(w, err)
		return
	}
	if !found {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(doc.JSON))
}

func (a *App) yggSearchMultiple(w http.ResponseWriter, r *http.Request) {
	if !a.yggGate(w, r) {
		return
	}
	var names []string
	decodeYggJSON(readYggJSON(r), &names)
	if names == nil {
		names = []string{}
	}
	out, err := a.ygg.SearchMultipleProfiles(r.Context(), names)
	if err != nil {
		a.yggError(w, err)
		return
	}
	if out == nil {
		out = []yggdrasil.Profile{}
	}
	jsonResponse(w, http.StatusOK, out)
}

func (a *App) yggSearchSingle(w http.ResponseWriter, r *http.Request) {
	if !a.yggGate(w, r) {
		return
	}
	profile, found, err := a.ygg.SearchSingleProfile(r.Context(), r.PathValue("username"))
	if err != nil {
		a.yggError(w, err)
		return
	}
	if !found {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	jsonResponse(w, http.StatusOK, profile)
}

// yggHello serves the ANY metadata entry. implementationVersion is the
// Go build version, never the PHP plugin version.
func (a *App) yggHello(w http.ResponseWriter, r *http.Request) {
	if !a.yggGate(w, r) {
		return
	}
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.yggError(w, err)
		return
	}
	locale := a.locale(r, nil)
	siteName, _ := site.LocalizedOption(options, "site_name", locale).(string)
	rawKey, _ := options["ygg_private_key"].(string)
	key, apiErr := yggdrasil.LoadForExport(rawKey)
	if apiErr != nil {
		a.yggError(w, apiErr)
		return
	}
	links := map[string]string{"homepage": a.cfg.BaseURL + "/"}
	state, err := a.modules.RequestState(r.Context())
	if err != nil {
		a.yggError(w, err)
		return
	}
	if !stateHasEnabled(state, "disable-registration") {
		links["register"] = a.cfg.BaseURL + "/auth/register"
	}
	domains := yggSkinDomains(options, r)
	version := a.buildVersion
	if version == "" {
		version = "m2-dev"
	}
	jsonResponse(w, http.StatusOK, map[string]any{
		"meta": map[string]any{
			"serverName":              siteName,
			"implementationName":      "Yggdrasil API for Blessing Skin",
			"implementationVersion":   version,
			"links":                   links,
			"feature.non_email_login": true,
		},
		"skinDomains":        domains,
		"signaturePublickey": yggdrasil.PublicKeyPEM(key),
	})
}

func yggSkinDomains(options map[string]any, r *http.Request) []string {
	var extra []string
	if raw, ok := options["ygg_skin_domain"].(string); ok && raw != "" {
		extra = strings.Split(raw, ",")
	}
	merged := append(append([]string{}, extra...), yggURLHost(options), yggRequestHost(r))
	seen := map[string]bool{}
	out := []string{}
	for _, domain := range merged {
		domain = strings.TrimSpace(domain)
		if !seen[domain] {
			seen[domain] = true
			out = append(out, domain)
		}
	}
	return out
}

func yggURLHost(options map[string]any) string {
	raw, ok := options["site_url"].(string)
	if !ok || raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func yggRequestHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

func (a *App) yggPublicKeys(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.YggdrasilPublicKeysEnabled {
		a.yggNotFound(w)
		return
	}
	if !a.yggGate(w, r) {
		return
	}
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.yggError(w, err)
		return
	}
	rawKey, _ := options["ygg_private_key"].(string)
	key, apiErr := yggdrasil.LoadForExport(rawKey)
	if apiErr != nil {
		a.yggError(w, apiErr)
		return
	}
	encoded := yggdrasil.PublicKeyBase64(key)
	jsonResponse(w, http.StatusOK, map[string]any{
		"profilePropertyKeys":   []map[string]string{{"publicKey": encoded}},
		"playerCertificateKeys": []map[string]string{{"publicKey": encoded}},
	})
}

// yggBearer extracts the Bearer credential and verifies it for the
// texture routes. Verification rechecks inside the business transaction.
func (a *App) yggBearer(w http.ResponseWriter, r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	token := ""
	if strings.HasPrefix(header, "Bearer ") {
		token = strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	}
	if token == "" {
		a.yggError(w, yggdrasil.ErrBearer)
		return "", false
	}
	return token, true
}

// yggGameError maps player business sentinels to protocol errors.
func (a *App) yggGameError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, yggdrasil.ErrModuleNotServed):
		a.yggNotFound(w)
	case errors.Is(err, players.ErrNotFound):
		a.yggError(w, yggdrasil.ErrPlayerNotFound404)
	case errors.Is(err, players.ErrTypeMismatch):
		a.yggError(w, &yggdrasil.APIError{Status: 400, Name: "IllegalArgumentException", Message: "Invalid texture size or type."})
	case errors.Is(err, textures.ErrNotPNG):
		a.yggError(w, &yggdrasil.APIError{Status: 400, Name: "IllegalArgumentException", Message: "Invalid texture file."})
	case errors.Is(err, players.ErrLackScore):
		a.yggError(w, &yggdrasil.APIError{Status: 403, Name: "ForbiddenOperationException", Message: "You don't have enough score to upload this texture."})
	case errors.Is(err, players.ErrStaleCredential):
		a.yggError(w, yggdrasil.ErrPlayerOwner)
	case errors.Is(err, players.ErrNotAuthorized):
		a.yggError(w, yggdrasil.ErrBearer)
	default:
		a.yggError(w, err)
	}
}

// replaceLastPNG strips the final ".png" occurrence like the legacy
// Str::replaceLast for the uploaded file name.
func replaceLastPNG(name string) string {
	index := strings.LastIndex(name, ".png")
	if index < 0 {
		return name
	}
	return name[:index] + name[index+len(".png"):]
}

func (a *App) yggUpload(w http.ResponseWriter, r *http.Request) {
	if !a.yggGate(w, r) {
		return
	}
	token, ok := a.yggBearer(w, r)
	if !ok {
		return
	}
	creds, err := a.ygg.VerifyBearerToken(r.Context(), token)
	if err != nil {
		a.yggGameError(w, err)
		return
	}
	creds.ProfileUUID = r.PathValue("uuid")
	slot := r.PathValue("type")
	// Stream the multipart file part to a staging file; the players
	// service publishes it only on success and the staging file is
	// always removed here.
	reader, err := r.MultipartReader()
	if err != nil {
		a.yggGameError(w, textures.ErrNotPNG)
		return
	}
	var staging string
	var model, fileName string
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			if staging != "" {
				_ = os.Remove(staging)
			}
			a.yggGameError(w, textures.ErrNotPNG)
			return
		}
		switch part.FormName() {
		case "file":
			tmp, err := os.CreateTemp("", "ygg-upload-*")
			if err != nil {
				_ = part.Close()
				a.yggGameError(w, err)
				return
			}
			staging = tmp.Name()
			fileName = part.FileName()
			if _, err := io.Copy(tmp, part); err != nil {
				_ = tmp.Close()
				_ = os.Remove(staging)
				_ = part.Close()
				a.yggGameError(w, err)
				return
			}
			_ = tmp.Close()
		case "model":
			value, _ := io.ReadAll(part)
			model = string(value)
		}
		_ = part.Close()
	}
	if staging == "" {
		a.yggGameError(w, textures.ErrNotPNG)
		return
	}
	defer func() { _ = os.Remove(staging) }()
	info, err := os.Stat(staging)
	if err != nil {
		a.yggGameError(w, err)
		return
	}
	if _, err := a.players.GameUpload(r.Context(), creds, a.ygg, slot, model, replaceLastPNG(fileName), staging, info.Size()); err != nil {
		a.yggGameError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) yggReset(w http.ResponseWriter, r *http.Request) {
	if !a.yggGate(w, r) {
		return
	}
	token, ok := a.yggBearer(w, r)
	if !ok {
		return
	}
	creds, err := a.ygg.VerifyBearerToken(r.Context(), token)
	if err != nil {
		a.yggGameError(w, err)
		return
	}
	creds.ProfileUUID = r.PathValue("uuid")
	if err := a.players.GameReset(r.Context(), creds, a.ygg, r.PathValue("type")); err != nil {
		a.yggGameError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// apiLocationHeader applies the global API Location Indicator: when the
// ygg_enable_ali option is on and the module is served, every response
// (not only API responses) carries the API root header.
func (a *App) apiLocationHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.modules != nil {
			served, err := a.servedModule(r.Context(), yggdrasilModule)
			if err == nil && served {
				if options, err := a.site.Options(r.Context()); err == nil && site.Truth(options["ygg_enable_ali"]) {
					w.Header().Set("X-Authlib-Injector-API-Location", a.cfg.BaseURL+"/api/yggdrasil")
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
