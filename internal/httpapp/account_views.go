package httpapp

import (
	"bytes"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/invitation"
	"blessing-skin-go/internal/modules"
	"blessing-skin-go/internal/reports"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/yggdrasil"
	"golang.org/x/net/html"
)

type Feature struct {
	Icon, Name  string
	Description template.HTML
}

// Strip tags follows the original trusted administrator CSS/JS and SEO slots.
// User fields never enter these raw slots.
func stripTags(value string, allowed map[string]bool) string {
	tokens := html.NewTokenizer(strings.NewReader(value))
	var out strings.Builder
	for {
		kind := tokens.Next()
		if kind == html.ErrorToken {
			return out.String()
		}
		if kind == html.TextToken {
			out.Write(tokens.Raw())
		} else if kind == html.StartTagToken || kind == html.EndTagToken || kind == html.SelfClosingTagToken {
			name, _ := tokens.TagName()
			if allowed[string(name)] {
				out.Write(tokens.Raw())
			}
		}
	}
}

var errSessionMissing = errors.New("httpapp: session missing")

func (a *App) populateView(r *http.Request, b *identity.BrowserSession, routeName string, options map[string]any, t func(string) string, view *ViewModel) error {
	messages, _ := r.Context().Value(messagesKey{}).(map[string]any)
	view.User = b.User
	if b.User != nil {
		tid, err := a.site.Avatar(r.Context(), b.User.UID)
		if err != nil {
			return err
		}
		view.AvatarWebP = a.cfg.BaseURL + "/avatar/" + strconv.FormatInt(tid, 10) + "?size=45"
		view.AvatarPNG = view.AvatarWebP + "&png=1"
	}
	view.Home = routeName == "/"
	view.ProfilePage = routeName == "user/profile"
	view.PlayersPage = routeName == "user/player"
	view.SkinlibPage = routeName == "skinlib" || strings.HasPrefix(routeName, "skinlib/")
	view.SkinlibShowPage = strings.HasPrefix(routeName, "skinlib/show/")
	view.SkinlibUploadPage = routeName == "skinlib/upload"
	view.HasUser = b.User != nil
	view.ClosetPage = routeName == "user/closet"
	view.AdminDashboardPage = routeName == "admin"
	view.ReportsPage = routeName == "user/reports"
	view.InvitationCodesPage = routeName == "admin/invitation-codes"
	view.YggdrasilConfigPage = routeName == "admin/yggdrasil-config"
	view.YggdrasilLogPage = routeName == "admin/yggdrasil-log"
	view.ReadmePage = routeName == "admin/yggdrasil-readme"
	if routeName == "user" {
		served, err := a.servedModule(r.Context(), yggdrasilModule)
		if err != nil {
			return err
		}
		if served && site.Truth(options["ygg_show_config_section"]) {
			locale := a.locale(r, b)
			text := func(key string) string { return modules.Message(key, locale) }
			view.YggDnd = &YggDndView{
				Title: text("Yggdrasil::dnd.title"), URLLabel: text("Yggdrasil::dnd.url"),
				Tip: text("Yggdrasil::dnd.tip"), Button: text("Yggdrasil::dnd.button"),
				Guide: text("Yggdrasil::dnd.guide"), APIRoot: a.cfg.BaseURL + "/api/yggdrasil",
			}
		}
	}
	if view.YggdrasilConfigPage {
		locale := a.locale(r, b)
		text := func(key string) string { return modules.Message(key, locale) }
		cfg := &view.YggConfig
		cfg.Title = text("Yggdrasil::config.title")
		view.Title = cfg.Title
		cfg.CommonTitle = text("Yggdrasil::config.common.title")
		cfg.KeypairTitle = text("Yggdrasil::config.keypair.title")
		cfg.APIRootLabel = text("Yggdrasil::config.url.label")
		cfg.APIRootNotice = text("Yggdrasil::config.url.notice")
		cfg.APIRoot = a.cfg.BaseURL + "/api/yggdrasil"
		cfg.UUIDAlgorithmTitle = text("Yggdrasil::config.common.ygg_uuid_algorithm.title")
		cfg.UUIDV3 = text("Yggdrasil::config.common.ygg_uuid_algorithm.v3")
		cfg.UUIDV4 = text("Yggdrasil::config.common.ygg_uuid_algorithm.v4")
		cfg.UUIDHint = text("Yggdrasil::config.common.ygg_uuid_algorithm.hint")
		cfg.TokenExpire1Title = text("Yggdrasil::config.common.ygg_token_expire_1.title")
		cfg.TokenExpire2Title = text("Yggdrasil::config.common.ygg_token_expire_2.title")
		cfg.TokenExpire2Desc = text("Yggdrasil::config.common.ygg_token_expire_2.description")
		cfg.TokensLimitTitle = text("Yggdrasil::config.common.ygg_tokens_limit.title")
		cfg.TokensLimitDesc = text("Yggdrasil::config.common.ygg_tokens_limit.description")
		cfg.RateLimitTitle = text("Yggdrasil::config.common.ygg_rate_limit.title")
		cfg.RateLimitHint = text("Yggdrasil::config.common.ygg_rate_limit.hint")
		cfg.SkinDomainTitle = text("Yggdrasil::config.common.ygg_skin_domain.title")
		cfg.SkinDomainDesc = text("Yggdrasil::config.common.ygg_skin_domain.description")
		cfg.SearchMaxTitle = text("Yggdrasil::config.common.ygg_search_profile_max.title")
		cfg.SearchMaxHint = text("Yggdrasil::config.common.ygg_search_profile_max.hint")
		cfg.ShowConfigTitle = text("Yggdrasil::config.common.ygg_show_config_section.title")
		cfg.ShowConfigLabel = text("Yggdrasil::config.common.ygg_show_config_section.label")
		cfg.EnableAliTitle = text("Yggdrasil::config.common.ygg_enable_ali.title")
		cfg.EnableAliLabel = text("Yggdrasil::config.common.ygg_enable_ali.label")
		cfg.PrivateKeyTitle = text("Yggdrasil::config.keypair.ygg_private_key.title")
		cfg.PrivateKeyHint = text("Yggdrasil::config.keypair.ygg_private_key.hint")
		cfg.GenerateLabel = text("Yggdrasil::config.keypair.ygg_private_key.generate")
		cfg.SubmitLabel = text("Yggdrasil::config.keypair.ygg_private_key.submit")
		cfg.KeypairMessage = text("Yggdrasil::config.keypair.ygg_private_key.message")
		cfg.ValidLabel = text("Yggdrasil::config.keypair.ygg_private_key.valid")
		cfg.InvalidLabel = text("Yggdrasil::config.keypair.ygg_private_key.invalid")
		cfg.SubmitLabel = t("general.submit")
		cfg.Values = map[string]string{}
		for _, key := range append(append([]string{}, yggConfigFields...), append(yggConfigCheckboxes, "ygg_private_key")...) {
			cfg.Values[key] = yggOptionString(options, key)
		}
		cfg.ShowConfigChecked = yggOptionChecked(options, "ygg_show_config_section")
		cfg.EnableAliChecked = yggOptionChecked(options, "ygg_enable_ali")
		_, keyErr := yggdrasil.ParsePrivateKey(cfg.Values["ygg_private_key"])
		cfg.PrivateKeyValid = keyErr == nil
		saved, err := a.takeFormError(r.Context(), b, yggConfigForm)
		if err != nil {
			return err
		}
		cfg.Saved = saved
	}
	if view.ReadmePage {
		view.YggReadme.Title = t("admin.plugins.readme")
		view.YggReadme.Back = t("general.back")
		var buffer bytes.Buffer
		if err := announcementMarkdown.Convert(a.assets.ReadmeYggdrasilAPI, &buffer); err != nil {
			return err
		}
		view.YggReadme.Content = template.HTML(buffer.String())
		view.Title = "Yggdrasil API"
	}
	if view.YggdrasilLogPage {
		locale := a.locale(r, b)
		text := func(key string) string { return modules.Message(key, locale) }
		log := &view.YggLog
		log.Title = text("Yggdrasil::log.title")
		view.Title = log.Title
		log.ActionLabel = text("Yggdrasil::log.header.action")
		log.ParamsLabel = text("Yggdrasil::log.header.params")
		log.TimeLabel = text("Yggdrasil::log.header.time")
		log.NoRecords = text("Yggdrasil::log.no-records")
		rows, page, hasNext, err := a.yggLogPageData(r)
		if err != nil {
			return err
		}
		for i := range rows {
			rows[i].ActionLabel = text("Yggdrasil::log.actions." + rows[i].Action)
			if rows[i].ActionLabel == "" || rows[i].ActionLabel == "Yggdrasil::log.actions."+rows[i].Action {
				rows[i].ActionLabel = text("Yggdrasil::log.actions.undefined")
			}
		}
		log.Rows = rows
		log.Page = page
		log.HasNext = hasNext
		log.HasPrev = page > 1
		if log.HasPrev {
			log.PrevURL = a.cfg.BaseURL + "/admin/yggdrasil-log?page=" + strconv.Itoa(page-1)
		}
		if log.HasNext {
			log.NextURL = a.cfg.BaseURL + "/admin/yggdrasil-log?page=" + strconv.Itoa(page+1)
		}
	}
	if routeName == "auth/register" {
		label, enabled, err := a.invitationEnabled(r.Context(), a.locale(r, b))
		if err != nil {
			return err
		}
		if enabled {
			view.Extra["invitation"] = map[string]string{"label": label}
		}
	}
	if view.InvitationCodesPage {
		locale := a.locale(r, b)
		text := func(key string) string { return modules.Message(key, locale) }
		view.Invitation.Title = text("InvitationCodes::admin.title")
		view.Invitation.FreeTitle = text("InvitationCodes::admin.available.title")
		view.Invitation.FreeEmpty = text("InvitationCodes::admin.available.empty")
		view.Invitation.UsedTitle = text("InvitationCodes::admin.used.title")
		view.Invitation.UsedEmpty = text("InvitationCodes::admin.used.empty")
		view.Invitation.AmountLabel = text("InvitationCodes::admin.available.amount")
		view.Invitation.AmountPlaceholder = text("InvitationCodes::admin.available.placeholder")
		view.Invitation.GenerateTitle = text("InvitationCodes::admin.title")
		// codes.twig renders its block title into <title> and the content h1.
		view.Title = view.Invitation.Title
		view.Invitation.CodeLabel = text("InvitationCodes::general.code")
		view.Invitation.GeneratedAtLabel = text("InvitationCodes::admin.generated_at")
		view.Invitation.UserLabel = text("InvitationCodes::admin.used.user_id")
		view.Invitation.UsedAtLabel = text("InvitationCodes::admin.used.used_at")
		error, err := a.takeFormError(r.Context(), b, invitationForm)
		if err != nil {
			return err
		}
		view.Invitation.Error = error
		codes, err := a.invitation.List(r.Context())
		if err != nil {
			return err
		}
		rows := func(source []invitation.Code) []InvitationRow {
			out := []InvitationRow{}
			for _, code := range source {
				row := InvitationRow{Code: code.Code, GeneratedAt: code.GeneratedAt.In(a.site.Location).Format("2006-01-02 15:04:05"), UsedBy: strconv.FormatInt(code.UsedBy, 10)}
				if code.UsedAt != nil {
					row.UsedAt = code.UsedAt.In(a.site.Location).Format("2006-01-02 15:04:05")
				}
				out = append(out, row)
			}
			return out
		}
		view.Invitation.Free = rows(codes.Free)
		view.Invitation.Used = rows(codes.Used)
	}
	if view.AdminDashboardPage {
		store := a.site.Store
		if err := store.DB.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM "+store.Table("users")).Scan(&view.AdminSumUsers); err != nil {
			return err
		}
		if err := store.DB.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM "+store.Table("players")).Scan(&view.AdminSumPlayers); err != nil {
			return err
		}
		if err := store.DB.QueryRowContext(r.Context(), "SELECT COUNT(*),CAST(COALESCE(SUM(size),0) AS SIGNED) FROM "+store.Table("textures")).Scan(&view.AdminSumTextures, &view.AdminSumStorage); err != nil {
			return err
		}
		view.AdminUsageUsers = t("admin.index.total-users")
		view.AdminUsagePlayers = t("admin.index.total-players")
		view.AdminUsageTextures = t("admin.index.total-textures")
		view.AdminUsageStorage = t("admin.index.disk-usage")
		view.AdminNotifyTitle = t("admin.notifications.send.title")
		view.AdminNotifyReceiver = t("admin.notifications.receiver.title")
		view.AdminNotifyAll = t("admin.notifications.receiver.all")
		view.AdminNotifyNormal = t("admin.notifications.receiver.normal")
		view.AdminNotifyUID = t("admin.notifications.receiver.uid")
		view.AdminNotifyEmail = t("admin.notifications.receiver.email")
		view.AdminNotifySubject = t("admin.notifications.title")
		view.AdminNotifyContent = t("admin.notifications.content")
		view.AdminOverview = t("admin.index.overview")
		view.PlayerManage = t("general.player-manage")
		view.AdminSubmit = t("general.submit")
		view.AdminStorageMB = strconv.FormatFloat(float64(view.AdminSumStorage)/1024, 'f', 1, 64)
		var err error
		view.NotificationError, err = a.takeFormError(r.Context(), b, notificationForm)
		if err != nil {
			return err
		}
		view.NotificationSent, err = a.takeFormError(r.Context(), b, notificationSentForm)
		if err != nil {
			return err
		}
	}
	if view.ClosetPage {
		view.ClosetUnverified = site.Truth(options["require_verification"]) && b.User != nil && !b.User.Verified
	}
	view.Bind = routeName == "auth/bind"
	view.Verify = strings.HasPrefix(routeName, "auth/verify/")
	view.Texts = map[string]string{}
	view.TextHTML = map[string]template.HTML{}
	// Only original template translation slots are rendered as trusted HTML.
	for _, key := range []string{"auth.email", "user.profile.avatar.title", "user.profile.avatar.notice", "user.profile.avatar.reset", "user.profile.password.title", "user.profile.password.old", "user.profile.password.new", "user.profile.password.confirm", "user.profile.password.button", "user.profile.nickname.title", "user.profile.email.title", "user.profile.email.new", "user.profile.email.password", "user.profile.email.button", "user.profile.delete.title", "user.profile.delete.admin", "user.profile.delete.button", "user.profile.delete.notice", "user.profile.delete.modal-title", "user.profile.delete.modal-notice", "user.profile.delete.password", "general.submit", "general.close", "index.features.title", "index.introduction", "index.start"} {
		value := strings.NewReplacer(":sitename", view.SiteName, ":site", view.SiteName).Replace(t(key))
		view.Texts[key] = value
		if key == "user.profile.avatar.notice" || key == "user.profile.delete.modal-notice" {
			view.TextHTML[key] = template.HTML(strings.ReplaceAll(value, "\n", "<br />\n"))
		}
	}
	if view.SkinlibPage {
		view.SkinlibClosetLink = t("general.my-closet")
		view.SkinlibUploadLink = t("skinlib.general.upload-new-skin")
		view.SkinlibLogin = t("general.anonymous")
		view.SkinlibLabel = t("general.skinlib")
		switch {
		case view.SkinlibShowPage:
			view.ShowTitle = t("skinlib.show.title")
			tid, convErr := strconv.ParseInt(r.PathValue("texture"), 10, 64)
			if convErr != nil {
				return convErr
			}
			row, getErr := a.textures.Get(r.Context(), tid)
			if getErr != nil {
				return getErr
			}
			nickname, admin, exists, ownerErr := a.textures.Owner(r.Context(), row.Uploader)
			if ownerErr != nil {
				return ownerErr
			}
			var inCloset bool
			if b.User != nil {
				count, err := a.site.CountClosetItem(r.Context(), b.User.UID, tid)
				if err != nil {
					return err
				}
				inCloset = count > 0
			}
			view.Extra["download"] = site.Truth(options["allow_downloading_texture"])
			view.Extra["currentUid"] = int64(0)
			view.Extra["admin"] = false
			if b.User != nil {
				view.Extra["currentUid"] = b.User.UID
				view.Extra["admin"] = b.User.Permission >= 1
			}
			view.Extra["inCloset"] = inCloset
			view.Extra["uploaderExists"] = exists
			if exists {
				view.Extra["nickname"] = nickname
			} else {
				view.Extra["nickname"] = t("general.unexistent-user")
			}
			view.Extra["report"] = site.Number(options["reporter_score_modification"])
			badges := []map[string]string{}
			if admin {
				badges = append(badges, map[string]string{"text": "STAFF", "color": "primary"})
			}
			view.Extra["badges"] = badges
		case view.SkinlibUploadPage:
			view.UploadTitle = t("skinlib.upload.title")
			regexp, _ := options["texture_name_regexp"].(string)
			rule := t("skinlib.upload.name-rule")
			if regexp != "" {
				rule = strings.ReplaceAll(t("skinlib.upload.name-rule-regexp"), ":regexp", regexp)
			}
			view.Extra["rule"] = rule
			view.Extra["privacyNotice"] = strings.ReplaceAll(t("skinlib.upload.private-score-notice"), ":score", strconv.FormatInt(site.Number(options["private_score_per_storage"]), 10))
			score, scoreErr := a.site.Score(r.Context(), b.User.UID)
			if scoreErr != nil {
				return scoreErr
			}
			view.Extra["score"] = score.User.Score
			view.Extra["scorePublic"] = site.Number(options["score_per_storage"])
			view.Extra["scorePrivate"] = site.Number(options["private_score_per_storage"])
			view.Extra["closetItemCost"] = site.Number(options["score_per_closet_item"])
			view.Extra["award"] = site.Number(options["score_award_per_texture"])
			policy, _ := site.LocalizedOption(options, "content_policy", view.Locale).(string)
			rendered, mdErr := renderAnnouncement(policy)
			if mdErr != nil {
				return mdErr
			}
			view.Extra["contentPolicy"] = string(rendered)
		default:
			if b.User != nil {
				view.Extra["currentUid"] = b.User.UID
			} else {
				view.Extra["currentUid"] = nil
			}
		}
	}
	if view.PlayersPage {
		if b.User == nil {
			return errSessionMissing
		}
		count, err := a.players.Count(r.Context(), b.User.UID)
		if err != nil {
			return err
		}
		score, err := a.site.Score(r.Context(), b.User.UID)
		if err != nil {
			return err
		}
		view.PlayerCount = count
		view.PlayerNoticeTitle = t("general.notice")
		view.PlayerNotice = t("user.player.login-notice")
		view.Extra["count"] = count
		view.Extra["rule"] = t("user.player.player-name-rule." + optionText(options["player_name_rule"]))
		view.Extra["length"] = strings.NewReplacer(":min", optionText(options["player_name_length_min"]), ":max", optionText(options["player_name_length_max"])).Replace(t("user.player.player-name-length"))
		view.Extra["score"] = score.User.Score
		view.Extra["cost"] = site.Number(options["score_per_player"])
	}
	if view.ReportsPage {
		path := a.cfg.BaseURL + strings.TrimPrefix(r.URL.Path, a.basePath)
		page, err := a.reports.Track(r.Context(), b, pageFromQuery(r), path)
		if err != nil {
			return err
		}
		statuses := statusLabels(messages, "front-end.report.status")
		view.ReportTID = t("front-end.report.tid")
		view.ReportReason = t("front-end.report.reason")
		view.ReportStatus = t("front-end.report.status-title")
		view.ReportTime = t("front-end.report.time")
		view.ReportPaginator = page
		tracked, _ := page.Data.([]reports.Report)
		for _, report := range tracked {
			status := ""
			if int(report.Status) >= 0 && int(report.Status) < len(statuses) {
				status = statuses[report.Status]
			}
			view.ReportRows = append(view.ReportRows, ReportRow{TID: report.TID, Reason: report.Reason, Status: status, ReportAt: report.ReportAt})
		}
	}
	if view.ClosetPage {
		view.Extra["unverified"] = view.ClosetUnverified
		view.Extra["rule"] = t("user.player.player-name-rule." + optionText(options["player_name_rule"]))
		view.Extra["length"] = strings.NewReplacer(":min", optionText(options["player_name_length_min"]), ":max", optionText(options["player_name_length_max"])).Replace(t("user.player.player-name-length"))
	}
	if view.Bind || view.Verify {
		form := "bind"
		if view.Verify {
			form = "verify"
		}
		var err error
		view.FormError, err = a.takeFormError(r.Context(), b, form)
		if err != nil {
			return err
		}
	}
	view.Favicon = optionText(options["favicon_url"])
	if !strings.HasPrefix(view.Favicon, "http") {
		view.Favicon = a.cfg.BaseURL + "/" + strings.TrimPrefix(view.Favicon, "/")
	}
	view.ThemeColor = map[string]string{"primary": "#007bff", "secondary": "#6c757d", "success": "#28a745", "warning": "#ffc107", "danger": "#dc3545", "navy": "#001f3f", "olive": "#3d9970", "lime": "#01ff70", "fuchsia": "#f012be", "maroon": "#d81b60", "indigo": "#6610f2", "purple": "#6f42c1", "pink": "#e83e8c", "orange": "#fd7e14", "teal": "#20c997", "cyan": "#17a2b8", "gray": "#6c757d"}[optionText(options["navbar_color"])]
	view.Keywords = optionText(options["meta_keywords"])
	view.Description = optionText(options["meta_description"])
	view.MetaExtras = template.HTML(stripTags(optionText(options["meta_extras"]), map[string]bool{"meta": true}))
	view.CDNHost = optionText(options["cdn_address"])
	view.CustomCSS = template.CSS(stripTags(optionText(options["custom_css"]), nil))
	view.CustomJS = template.JS(stripTags(optionText(options["custom_js"]), map[string]bool{"div": true, "span": true, "ul": true, "li": true, "p": true, "a": true, "img": true, "i": true}))
	// Hooks are supplied by the installed application composition, never by
	// request fields. Their owners retain the legacy head/foot ordering.
	view.HeadLinks = a.site.HeadLinks
	view.ExtraHead = a.site.ExtraHead
	view.Scripts = a.site.Scripts
	view.ExtraFoot = a.site.ExtraFoot
	view.Extra["recaptcha"] = options["recaptcha_sitekey"]
	view.Extra["invisible"] = site.Truth(options["recaptcha_invisible"])
	switch {
	case routeName == "auth/login":
		fails, err := a.captcha.LoginFailures(r.Context(), clientIP(r))
		if err != nil {
			return err
		}
		view.Extra["tooManyFails"] = fails > 3
	case routeName == "auth/register":
		view.Extra["player"] = site.Truth(options["register_with_player_name"])
		view.LoginNotice = strings.ReplaceAll(t("auth.register.message"), ":sitename", view.SiteName)
	case routeName == "auth/forgot":
		view.LoginNotice = t("auth.forgot.message")
	case strings.HasPrefix(routeName, "auth/reset/"):
		uid, err := challengeUID(r)
		if err != nil {
			return err
		}
		u, err := a.accounts.InspectChallenge(r.Context(), uid, "reset", r.URL.Query().Get("token"))
		if err != nil {
			return err
		}
		view.LoginNotice = strings.ReplaceAll(t("auth.reset.message"), ":username", u.Nickname)
	case view.Bind || view.Verify:
		view.LoginNotice = t("auth.bind.message")
		view.FormIntroduction = t("auth.bind.introduction")
		view.FormButton = t("general.submit")
		if view.Bind {
			view.FormButton = t("auth.bind.button")
		}
	}
	if view.Home {
		view.Title = view.SiteName
		view.SiteDescription = optionText(site.LocalizedOption(options, "site_description", view.Locale))
		view.HomePicture = optionText(options["home_pic_url"])
		if !site.Truth(options["home_pic_url"]) {
			view.HomePicture = "./app/bg.webp"
		}
		view.Skinlib = t("general.skinlib")
		view.LoginLabel = t("general.login")
		view.RegisterLabel = t("general.register")
		view.FixedBackground = site.Truth(options["fixed_bg"])
		view.TransparentNavbar = site.Truth(options["transparent_navbar"])
		view.HideIntroduction = site.Truth(options["hide_intro"])
		view.Extra["transparent_navbar"] = view.TransparentNavbar
		for _, item := range []string{"first", "second", "third"} {
			view.Features = append(view.Features, Feature{t("index.features." + item + ".icon"), t("index.features." + item + ".name"), template.HTML(t("index.features." + item + ".desc"))})
		}
		for _, file := range a.assets.Manifest["home-css"] {
			if strings.HasSuffix(file, ".css") {
				view.HomeCSS = append(view.HomeCSS, a.cfg.BaseURL+"/app/"+file)
			}
		}
		for _, file := range a.assets.Manifest["home"] {
			if strings.HasSuffix(file, ".js") {
				view.HomeJS = append(view.HomeJS, a.cfg.BaseURL+"/app/"+file)
			}
		}
	}
	return nil
}

func statusLabels(messages map[string]any, key string) []string {
	value, _ := lookupValue(messages, key).([]any)
	out := make([]string, 0, len(value))
	for _, item := range value {
		text, _ := item.(string)
		out = append(out, text)
	}
	return out
}

func lookupValue(table map[string]any, key string) any {
	parts := strings.Split(key, ".")
	var value any = table
	for _, part := range parts {
		m, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = m[part]
	}
	return value
}
