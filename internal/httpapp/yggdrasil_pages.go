package httpapp

import (
	"net/http"
	"strconv"

	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/yggdrasil"
)

// yggConfigForm is the flash form for the module config save roundtrip.
const yggConfigForm = "ygg-cfg"

// yggConfigFields lists the common form option keys in legacy order.
var yggConfigFields = []string{
	"ygg_uuid_algorithm", "ygg_token_expire_1", "ygg_token_expire_2",
	"ygg_tokens_limit", "ygg_rate_limit", "ygg_skin_domain",
	"ygg_search_profile_max",
}

// yggConfigCheckboxes lists the common form checkbox keys.
var yggConfigCheckboxes = []string{"ygg_show_config_section", "ygg_enable_ali"}

// yggConfig serves the module config page (GET) and saves one form per
// submission (POST with option=common|keypair), mirroring the legacy
// OptionForm handle: only the submitted form's items are written.
func (a *App) yggConfig(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	served, err := a.servedModule(r.Context(), yggdrasilModule)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !served {
		a.errorPage(w, r, http.StatusNotFound, "admin.plugins.operations.no-config-notice")
		return
	}
	if r.Method != http.MethodPost {
		a.render(w, r, b, "admin/yggdrasil-config", "", false)
		return
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	form := v.text("option")
	var keys []string
	switch form {
	case "common":
		keys = append(append([]string{}, yggConfigFields...), yggConfigCheckboxes...)
	case "keypair":
		keys = []string{"ygg_private_key"}
	default:
		a.errorPage(w, r, http.StatusNotFound, "admin.plugins.operations.no-config-notice")
		return
	}
	for _, key := range keys {
		value := v.text(key)
		if isCheckboxKey(key) {
			if _, present := r.Form[key]; !present {
				value = "false"
			}
		}
		if err := a.setOption(r, key, value); err != nil {
			a.serverError(w, r, b)
			return
		}
	}
	if err := a.putFlash(r.Context(), b, yggConfigForm, a.message(r, b, "options.option-saved")); err != nil {
		a.serverError(w, r, b)
		return
	}
	http.Redirect(w, r, a.cfg.BaseURL+"/admin/plugins/config/yggdrasil-api", http.StatusFound)
}

func isCheckboxKey(key string) bool {
	for _, checkbox := range yggConfigCheckboxes {
		if checkbox == key {
			return true
		}
	}
	return false
}

// setOption updates every row of one option name, inserting when absent.
func (a *App) setOption(r *http.Request, name, value string) error {
	store := a.site.Store
	result, err := store.DB.ExecContext(r.Context(), "UPDATE "+store.Table("options")+" SET option_value=? WHERE option_name=?", value, name)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		_, err = store.DB.ExecContext(r.Context(), "INSERT INTO "+store.Table("options")+" (option_name,option_value) VALUES (?,?)", name, value)
	}
	return err
}

// yggGenerate returns one candidate 4096-bit private key. The candidate
// is returned to the browser only; it reaches the options table solely
// through the explicit keypair form submission.
func (a *App) yggGenerate(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	served, err := a.servedModule(r.Context(), yggdrasilModule)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !served {
		a.errorPage(w, r, http.StatusNotFound, "admin.plugins.operations.no-config-notice")
		return
	}
	if _, ok := a.body(w, r, b); !ok {
		return
	}
	key, err := yggdrasil.GeneratePrivateKeyPEM()
	if err != nil {
		// Legacy json('Error: ...', 1) renders HTTP 200 with code 1.
		jsonResponse(w, http.StatusOK, map[string]any{"code": 1, "message": "Error: " + err.Error()})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "key": key})
}

// yggReadme serves the frozen admin readme page for the Yggdrasil module.
// The original controller rendered the plugin's README.md for any plugin
// directory that contained one, without an enabled check; the Go module
// ships the frozen README.md as a static asset and renders it through the
// same page shape.
func (a *App) yggReadme(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.render(w, r, b, "admin/yggdrasil-readme", "", false)
}

// yggLogPage serves the admin log reader. The route is always
// registered; only the sidebar entry follows the verbose switch.
func (a *App) yggLogPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.render(w, r, b, "admin/yggdrasil-log", "", false)
}

// yggLogPageData loads one page of ten newest-first entries with
// desensitized parameters for rendering. An invalid page parameter
// falls back to the first page, matching the legacy paginator.
func (a *App) yggLogPageData(r *http.Request) ([]YggLogRow, int, bool, error) {
	page := 1
	if raw := r.URL.Query().Get("page"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 1 {
			page = parsed
		}
	}
	stored, err := a.ygg.ListLogsPage(r.Context(), 11, (page-1)*10)
	if err != nil {
		return nil, 0, false, err
	}
	hasNext := len(stored) > 10
	if hasNext {
		stored = stored[:10]
	}
	rows := make([]YggLogRow, 0, len(stored))
	for _, entry := range stored {
		rows = append(rows, YggLogRow{
			ID: entry.ID, Action: entry.Action, UserID: entry.UserID, PlayerID: entry.PlayerID,
			Parameters: yggdrasil.SanitizeStoredParameters(entry.Parameters),
			IP:         entry.IP, Time: entry.Time,
		})
	}
	return rows, page, hasNext, nil
}

// yggOptionString renders one current option value for the config form.
func yggOptionString(options map[string]any, key string) string {
	return optionText(options[key])
}

// yggOptionChecked reports the config checkbox state from the option map.
func yggOptionChecked(options map[string]any, key string) bool {
	return site.Truth(options[key])
}

// YggConfigView carries the legacy config.twig contract: the API root
// card plus the common and keypair forms with their current values.
type YggConfigView struct {
	Title, CommonTitle, KeypairTitle                            string
	APIRootLabel, APIRootNotice, APIRoot                        string
	UUIDAlgorithmTitle, UUIDV3, UUIDV4, UUIDHint                string
	TokenExpire1Title, TokenExpire2Title, TokenExpire2Desc      string
	TokensLimitTitle, TokensLimitDesc                           string
	RateLimitTitle, RateLimitHint                               string
	SkinDomainTitle, SkinDomainDesc                             string
	SearchMaxTitle, SearchMaxHint                               string
	ShowConfigTitle, ShowConfigLabel                            string
	EnableAliTitle, EnableAliLabel                              string
	PrivateKeyTitle, PrivateKeyHint, GenerateLabel, SubmitLabel string
	KeypairMessage, ValidLabel, InvalidLabel                    string
	Values                                                      map[string]string
	ShowConfigChecked, EnableAliChecked                         bool
	PrivateKeyValid                                             bool
	Saved                                                       string
}

// YggLogRow is one desensitized log entry for the admin reader.
type YggLogRow struct {
	ID, UserID, PlayerID                      int64
	Action, ActionLabel, Parameters, IP, Time string
}

// YggLogView carries the legacy log.twig contract for one page.
type YggLogView struct {
	Title, ActionLabel, ParamsLabel, TimeLabel, NoRecords string
	Rows                                                  []YggLogRow
	Page                                                  int
	HasNext, HasPrev                                      bool
	PrevURL, NextURL                                      string
}

// YggDndView carries the legacy dnd.twig contract for the user center.
type YggDndView struct {
	Title, URLLabel, Tip, Button, Guide, APIRoot string
}
