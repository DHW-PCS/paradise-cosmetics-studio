package httpapp

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/mail"
	"strconv"
	"time"
	"unicode/utf8"

	"paradise-cosmetics-studio/internal/account"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/invitation"
	"paradise-cosmetics-studio/internal/legacy/rules"
	"paradise-cosmetics-studio/internal/modules"
	"paradise-cosmetics-studio/internal/site"
)

func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
func (a *App) body(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) (input, bool) {
	v, err := decode(r)
	if err != nil {
		validation(w, map[string][]string{"request": {a.fieldMessage(r, b, "request", "json")}})
		return nil, false
	}
	return v, a.csrf(w, r, b, v)
}
func (a *App) requiredText(r *http.Request, b *identity.BrowserSession, v input, fields map[string][]string, key string, min, max int) {
	raw := v.text(key)
	if raw == "" {
		fields[key] = []string{a.fieldMessage(r, b, key, "required")}
	} else if utf8.RuneCountInString(raw) < min {
		fields[key] = []string{a.fieldMessage(r, b, key, "min.string", ":min", strconv.Itoa(min))}
	} else if max > 0 && utf8.RuneCountInString(raw) > max {
		fields[key] = []string{a.fieldMessage(r, b, key, "max.string", ":max", strconv.Itoa(max))}
	}
}
func (a *App) emailField(r *http.Request, b *identity.BrowserSession, v input, fields map[string][]string) {
	a.requiredText(r, b, v, fields, "email", 1, 0)
	if v.text("email") != "" {
		addr, err := mail.ParseAddress(v.text("email"))
		if err != nil || addr.Address != v.text("email") {
			fields["email"] = []string{a.fieldMessage(r, b, "email", "email")}
		}
	}
}
func (a *App) checkCaptcha(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, v input) bool {
	if v.text("captcha") == "" {
		validation(w, map[string][]string{"captcha": {a.fieldMessage(r, b, "captcha", "required")}})
		return false
	}
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return false
	}
	secret, _ := options["recaptcha_secretkey"].(string)
	valid, err := a.captcha.Check(r.Context(), b, v.text("captcha"), secret)
	if err != nil {
		a.serverError(w, r, b)
		return false
	}
	if !valid {
		key := "validation.captcha"
		if secret != "" {
			key = "validation.recaptcha"
		}
		validation(w, map[string][]string{"captcha": {a.message(r, b, key)}})
	}
	return valid
}
func (a *App) captchaImage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
		if _, ok := a.body(w, r, b); !ok {
			return
		}
	}
	pixels, err := a.captcha.Generate(r.Context(), b)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(pixels)
}
func (a *App) guest(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) bool {
	if b.User != nil {
		http.Redirect(w, r, a.cfg.BaseURL+"/user", 302)
		return false
	}
	return true
}
func (a *App) registerPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if a.guest(w, r, b) {
		a.render(w, r, b, "auth/register", "auth.register.title", true)
	}
}
func (a *App) forgotPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.guest(w, r, b) {
		return
	}
	if a.accounts.Mail == nil {
		a.errorPage(w, r, 500, "auth.forgot.disabled")
		return
	}
	a.render(w, r, b, "auth/forgot", "auth.forgot.title", true)
}
func (a *App) profilePage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.render(w, r, b, "user/profile", "general.profile", false)
}
func (a *App) bindPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.render(w, r, b, "auth/bind", "auth.bind.title", true)
}
func (a *App) homePage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.render(w, r, b, "/", "", false)
}

func (a *App) registerAccount(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.guest(w, r, b) {
		return
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	fields := map[string][]string{}
	a.emailField(r, b, v, fields)
	a.requiredText(r, b, v, fields, "password", 8, 32)
	if site.Truth(options["register_with_player_name"]) {
		name := v.text("player_name")
		a.requiredText(r, b, v, fields, "player_name", int(site.Number(options["player_name_length_min"])), int(site.Number(options["player_name_length_max"])))
		valid, err := rules.MatchPlayer(optionText(options["player_name_rule"]), optionText(options["custom_player_name_regexp"]), name)
		if err != nil {
			a.serverError(w, r, b)
			return
		}
		if name != "" && !valid {
			fields["player_name"] = []string{a.message(r, b, "user.player.player-name-rule."+optionText(options["player_name_rule"]))}
		}
	} else {
		a.requiredText(r, b, v, fields, "nickname", 1, 255)
	}
	if len(fields) > 0 {
		validation(w, fields)
		return
	}
	if !a.checkCaptcha(w, r, b, v) {
		return
	}
	result, err := a.accounts.Register(r.Context(), account.Registration{Email: v.text("email"), Nickname: v.text("nickname"), PlayerName: v.text("player_name"), Password: v.text("password"), IP: clientIP(r), Locale: a.locale(r, b), Guest: b.Token, InvitationCode: v.text("invitationCode")})
	switch {
	case errors.Is(err, account.ErrEmailUsed):
		validation(w, map[string][]string{"email": {a.fieldMessage(r, b, "email", "unique")}})
		return
	case errors.Is(err, account.ErrPlayerUsed):
		a.business(w, r, b, 1, "user.player.add.repeated")
		return
	case errors.Is(err, account.ErrIPQuota):
		a.business(w, r, b, 1, "auth.register.max", ":regs", optionText(options["regs_per_ip"]))
		return
	case errors.Is(err, invitation.ErrEmpty), errors.Is(err, invitation.ErrUnavailable):
		// The original can_register filter rejected with the plugin message;
		// the code keeps the original json(reason, 1) shape.
		key := "InvitationCodes::messages.empty"
		if errors.Is(err, invitation.ErrUnavailable) {
			key = "InvitationCodes::messages.invalid"
		}
		jsonResponse(w, 200, map[string]any{"code": 1, "message": modules.Message(key, a.locale(r, b))})
		return
	case errors.Is(err, account.ErrModuleUnavailable):
		// An enabled restricting module without a connected consumer refuses
		// the whole registration. The original can_register filter rejected
		// with a code=1 JSON (legacy disable-registration uses its general
		// title text); a deployment config failure (verification without
		// mail) stays a 503 server error via the generic branch below.
		jsonResponse(w, 200, map[string]any{"code": 1, "message": modules.Message("ParadiseCosmeticsStudio\\DisableRegistration::general.title", a.locale(r, b))})
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	a.cookie(w, sessionCookie, result.Token, time.Time{})
	a.business(w, r, b, 0, "auth.register.success")
}
func (a *App) business(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, code int, key string, params ...string) {
	message := ""
	if key != "" {
		message = a.message(r, b, key, params...)
	}
	jsonResponse(w, 200, map[string]any{"code": code, "message": message})
}
func (a *App) sign(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if _, ok := a.body(w, r, b); !ok {
		return
	}
	result, err := a.accounts.Sign(r.Context(), b)
	if errors.Is(err, account.ErrTooSoon) {
		a.business(w, r, b, 1, "")
		return
	}
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, 200, map[string]any{"code": 0, "message": a.message(r, b, "user.sign-success", ":score", strconv.FormatInt(result.Award, 10)), "data": map[string]int64{"score": result.Score}})
}
func (a *App) bindEmail(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	fields := map[string][]string{}
	a.emailField(r, b, v, fields)
	if len(fields) > 0 {
		a.formValidation(w, r, b, "bind", fields)
		return
	}
	err := a.accounts.BindEmail(r.Context(), b, v.text("email"))
	if errors.Is(err, account.ErrEmailUsed) {
		a.formValidation(w, r, b, "bind", map[string][]string{"email": {a.fieldMessage(r, b, "email", "unique")}})
		return
	}
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	http.Redirect(w, r, a.cfg.BaseURL+"/user", 302)
}
func (a *App) profile(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	action := v.text("action")
	if _, exists := v["action"]; !exists {
		action = r.URL.Query().Get("action")
	}
	fields := map[string][]string{}
	var err error
	switch action {
	case "nickname":
		a.requiredText(r, b, v, fields, "new_nickname", 1, 0)
	case "password":
		a.requiredText(r, b, v, fields, "current_password", 6, 32)
		a.requiredText(r, b, v, fields, "new_password", 8, 32)
	case "email":
		a.emailField(r, b, v, fields)
		a.requiredText(r, b, v, fields, "password", 6, 32)
	case "delete":
		a.requiredText(r, b, v, fields, "password", 6, 32)
	default:
		a.business(w, r, b, 1, "general.illegal-parameters")
		return
	}
	if len(fields) > 0 {
		validation(w, fields)
		return
	}
	if action == "nickname" {
		err = a.accounts.Nickname(r.Context(), b, v.text("new_nickname"))
	} else {
		current := v.text("password")
		value := v.text("email")
		if action == "password" {
			current = v.text("current_password")
			value = v.text("new_password")
		}
		err = a.accounts.ChangeProfile(r.Context(), b, action, current, value)
	}
	prefix := "user.profile." + action + "."
	switch {
	case errors.Is(err, identity.ErrCredentials):
		a.business(w, r, b, 1, prefix+"wrong-password")
		return
	case errors.Is(err, account.ErrForbidden) && action == "delete":
		a.business(w, r, b, 1, prefix+"admin")
		return
	case errors.Is(err, account.ErrEmailUsed):
		a.business(w, r, b, 1, prefix+"existed")
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	if action != "nickname" {
		a.cookie(w, sessionCookie, "", time.Unix(1, 0))
		a.cookie(w, rememberCookie, "", time.Unix(1, 0))
	}
	a.business(w, r, b, 0, prefix+"success", ":nickname", v.text("new_nickname"))
}
func integerValue(v input, key string) (int64, error) {
	raw := ""
	switch value := v[key].(type) {
	case string:
		raw = value
	case json.Number:
		raw = string(value)
	}
	return strconv.ParseInt(raw, 10, 64)
}
func (a *App) avatar(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	tid, err := integerValue(v, "tid")
	if err != nil {
		validation(w, map[string][]string{"tid": {a.fieldMessage(r, b, "tid", "integer")}})
		return
	}
	err = a.accounts.Avatar(r.Context(), b, tid)
	switch {
	case errors.Is(err, account.ErrNotFound):
		a.business(w, r, b, 1, "skinlib.non-existent")
	case errors.Is(err, account.ErrAvatarType):
		a.business(w, r, b, 1, "user.profile.avatar.wrong-type")
	case errors.Is(err, account.ErrPrivateTexture):
		a.business(w, r, b, 1, "skinlib.show.private")
	case err != nil:
		a.serverError(w, r, b)
	default:
		a.business(w, r, b, 0, "user.profile.avatar.success")
	}
}
func (a *App) forgotPassword(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.guest(w, r, b) {
		return
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	fields := map[string][]string{}
	a.emailField(r, b, v, fields)
	if len(fields) > 0 {
		validation(w, fields)
		return
	}
	if !a.checkCaptcha(w, r, b, v) {
		return
	}
	if a.accounts.Mail == nil {
		a.business(w, r, b, 1, "auth.forgot.disabled")
		return
	}
	err := a.accounts.Forgot(r.Context(), v.text("email"), clientIP(r), a.locale(r, b))
	switch {
	case errors.Is(err, account.ErrTooSoon):
		a.business(w, r, b, 2, "auth.forgot.frequent-mail")
	case errors.Is(err, account.ErrNotFound):
		a.business(w, r, b, 1, "auth.forgot.unregistered")
	case err != nil:
		a.serverError(w, r, b)
	default:
		a.business(w, r, b, 0, "auth.forgot.success")
	}
}
func challengeUID(r *http.Request) (int64, error) {
	key := "uid"
	if r.PathValue("user") != "" {
		key = "user"
	}
	return strconv.ParseInt(r.PathValue(key), 10, 64)
}
func (a *App) resetPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.guest(w, r, b) {
		return
	}
	if !a.inspectChallenge(w, r, b, "reset") {
		return
	}
	a.render(w, r, b, "auth/reset/"+r.PathValue("uid"), "auth.reset.title", true)
}
func (a *App) verifyPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !site.Truth(options["require_verification"]) {
		a.errorPage(w, r, 500, "user.verification.disabled")
		return
	}
	if !a.inspectChallenge(w, r, b, "verify") {
		return
	}
	a.render(w, r, b, "auth/verify/"+r.PathValue("user"), "auth.verify.title", true)
}
func (a *App) inspectChallenge(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, purpose string) bool {
	uid, err := challengeUID(r)
	if err != nil {
		a.errorPage(w, r, 403, "auth."+purpose+".invalid")
		return false
	}
	_, err = a.accounts.InspectChallenge(r.Context(), uid, purpose, r.URL.Query().Get("token"))
	if errors.Is(err, account.ErrInvalidChallenge) {
		a.errorPage(w, r, 403, "auth."+purpose+".invalid")
		return false
	}
	if err != nil {
		a.serverError(w, r, b)
		return false
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	return true
}
func (a *App) resetPassword(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.guest(w, r, b) {
		return
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	fields := map[string][]string{}
	a.requiredText(r, b, v, fields, "password", 8, 32)
	if len(fields) > 0 {
		validation(w, fields)
		return
	}
	uid, err := challengeUID(r)
	if err == nil {
		err = a.accounts.ResetPassword(r.Context(), uid, r.URL.Query().Get("token"), v.text("password"))
	} else {
		err = account.ErrInvalidChallenge
	}
	if errors.Is(err, account.ErrInvalidChallenge) {
		a.errorPage(w, r, 403, "auth.reset.invalid")
		return
	}
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	a.business(w, r, b, 0, "auth.reset.success")
}
func (a *App) verifyEmail(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	fields := map[string][]string{}
	a.emailField(r, b, v, fields)
	if len(fields) > 0 {
		a.formValidation(w, r, b, "verify", fields)
		return
	}
	uid, err := challengeUID(r)
	if err == nil {
		err = a.accounts.Verify(r.Context(), uid, r.URL.Query().Get("token"), v.text("email"))
	} else {
		err = account.ErrInvalidChallenge
	}
	if errors.Is(err, account.ErrEmailMismatch) {
		a.redirectFormError(w, r, b, "verify", a.message(r, b, "auth.verify.not-matched"))
		return
	}
	if errors.Is(err, account.ErrVerificationDisabled) {
		a.errorPage(w, r, 500, "user.verification.disabled")
		return
	}
	if errors.Is(err, account.ErrInvalidChallenge) {
		a.errorPage(w, r, 403, "auth.verify.invalid")
		return
	}
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	http.Redirect(w, r, a.cfg.BaseURL+"/user", 302)
}
func (a *App) sendVerification(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if _, ok := a.body(w, r, b); !ok {
		return
	}
	err := a.accounts.SendVerification(r.Context(), b, a.locale(r, b))
	key := ""
	switch {
	case errors.Is(err, account.ErrTooSoon):
		key = "frequent-mail"
	case errors.Is(err, account.ErrAlreadyVerified):
		key = "verified"
	case errors.Is(err, account.ErrVerificationDisabled):
		key = "disabled"
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	if key != "" {
		a.business(w, r, b, 1, "user.verification."+key)
		return
	}
	a.business(w, r, b, 0, "user.verification.success")
}
func (a *App) adminAccount(action string) func(http.ResponseWriter, *http.Request, *identity.BrowserSession) {
	return func(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
		v, ok := a.body(w, r, b)
		if !ok {
			return
		}
		uid, err := strconv.ParseInt(r.PathValue("user"), 10, 64)
		if err != nil {
			a.notFound(w, r)
			return
		}
		fields := map[string][]string{}
		value := v.text(action)
		switch action {
		case "email":
			a.emailField(r, b, v, fields)
		case "nickname":
			a.requiredText(r, b, v, fields, "nickname", 1, 0)
		case "password":
			a.requiredText(r, b, v, fields, "password", 8, 16)
		case "score":
			if raw, present := v["score"]; !present || raw == nil {
				fields["score"] = []string{a.fieldMessage(r, b, "score", "required")}
			} else if score, err := integerValue(v, "score"); err != nil {
				fields["score"] = []string{a.fieldMessage(r, b, "score", "integer")}
			} else {
				value = strconv.FormatInt(score, 10)
			}
		case "permission":
			p, err := integerValue(v, "permission")
			if err != nil || (p != -1 && p != 0 && p != 1) {
				fields["permission"] = []string{a.fieldMessage(r, b, "permission", "in")}
			}
			value = strconv.FormatInt(p, 10)
		}
		if len(fields) > 0 {
			validation(w, fields)
			return
		}
		err = a.accounts.AdminChange(r.Context(), b, uid, action, value)
		switch {
		case errors.Is(err, account.ErrForbidden):
			jsonResponse(w, 403, map[string]any{"code": 1, "message": a.message(r, b, "admin.users.operations.no-permission")})
			return
		case errors.Is(err, account.ErrNotFound):
			a.notFound(w, r)
			return
		case errors.Is(err, account.ErrEmailUsed):
			validation(w, map[string][]string{"email": {a.fieldMessage(r, b, "email", "unique")}})
			return
		case err != nil:
			a.serverError(w, r, b)
			return
		}
		key := "admin.users.operations." + action + ".success"
		if action == "permission" {
			key = "admin.users.operations.permission"
		}
		a.business(w, r, b, 0, key, ":new", value)
	}
}
