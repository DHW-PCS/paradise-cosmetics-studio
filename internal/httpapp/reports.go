package httpapp

import (
	"errors"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/notifications"
	"blessing-skin-go/internal/reports"
)

func (a *App) userReportsPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.render(w, r, b, "user/reports", "general.my-reports", false)
}

// pageFromQuery mirrors Paginator::resolveCurrentPage (invalid values fall back
// to page 1).
func pageFromQuery(r *http.Request) int {
	if parsed, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && parsed > 0 {
		return parsed
	}
	return 1
}

func (a *App) userReportList(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	path := a.cfg.BaseURL + strings.TrimPrefix(r.URL.Path, a.basePath)
	list, err := a.reports.Track(r.Context(), b, pageFromQuery(r), path)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, http.StatusOK, list)
}

func (a *App) reportSubmit(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !a.requireVerified(w, r, b, options) {
		return
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	fields := map[string][]string{}
	tid, tidErr := integerValue(v, "tid")
	if tidErr != nil {
		fields["tid"] = []string{a.fieldMessage(r, b, "tid", "integer")}
	}
	reason := v.text("reason")
	if reason == "" {
		fields["reason"] = []string{a.fieldMessage(r, b, "reason", "required")}
	}
	if len(fields) > 0 {
		validation(w, fields)
		return
	}
	err = a.reports.Submit(r.Context(), b, tid, reason)
	switch {
	case errors.Is(err, reports.ErrNotFound):
		validation(w, map[string][]string{"tid": {a.fieldMessage(r, b, "tid", "exists")}})
		return
	case errors.Is(err, reports.ErrRepeated):
		a.business(w, r, b, 1, "skinlib.report.duplicate")
		return
	case errors.Is(err, reports.ErrLackScore):
		a.business(w, r, b, 1, "skinlib.upload.lack-score")
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	a.business(w, r, b, 0, "skinlib.report.success")
}

func (a *App) adminDashboard(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.render(w, r, b, "admin", "general.dashboard", false)
}

func (a *App) adminReportsPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.render(w, r, b, "admin/reports", "general.report-manage", false)
}

func (a *App) adminReportList(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	page := 1
	if parsed, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil {
		page = parsed
	}
	path := a.cfg.BaseURL + strings.TrimPrefix(r.URL.Path, a.basePath)
	value, err := a.reports.Manage(r.Context(), page, r.URL.Query().Get("q"), path)
	if err != nil {
		a.searchError(w, r, b, err)
		return
	}
	jsonResponse(w, http.StatusOK, value)
}

func (a *App) adminReportReview(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	id, err := strconv.ParseInt(r.PathValue("report"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	action := v.text("action")
	if action != "delete" && action != "ban" && action != "reject" {
		validation(w, map[string][]string{"action": {a.fieldMessage(r, b, "action", "in")}})
		return
	}
	result, err := a.reports.Review(r.Context(), b, id, action)
	switch {
	case errors.Is(err, reports.ErrNotFound):
		a.notFound(w, r)
		return
	case errors.Is(err, reports.ErrNoPermission):
		a.business(w, r, b, 1, "admin.users.operations.no-permission")
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	message := a.message(r, b, "general.op-success")
	if result.TextureAlreadyDeleted {
		message = a.message(r, b, "general.texture-deleted")
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": message, "data": map[string]int64{"status": result.Status}})
}

func (a *App) unreadNotifications(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	list, err := a.notifications.Unread(r.Context(), b.User.UID)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, http.StatusOK, list)
}

func (a *App) readNotification(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if _, ok := a.body(w, r, b); !ok {
		return
	}
	read, err := a.notifications.Read(r.Context(), b.User.UID, r.PathValue("id"))
	if errors.Is(err, notifications.ErrNotFound) {
		a.notFound(w, r)
		return
	}
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	rendered, err := renderAnnouncement(read.Content)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"title": read.Title, "content": string(rendered), "time": read.Time})
}

func (a *App) adminSendNotification(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	jsonRequest := strings.Contains(r.Header.Get("Accept"), "application/json")
	formError := func(message string) {
		if err := a.putFormError(r.Context(), b, notificationForm, message); err != nil {
			a.serverError(w, r, b)
			return
		}
		http.Redirect(w, r, a.cfg.BaseURL+"/admin", http.StatusFound)
	}
	fail := func(fields map[string][]string) {
		if jsonRequest {
			validation(w, fields)
			return
		}
		message := ""
		for _, values := range fields {
			if len(values) > 0 {
				message = values[0]
				break
			}
		}
		formError(message)
	}
	fields := map[string][]string{}
	receiver := v.text("receiver")
	if receiver != "all" && receiver != "normal" && receiver != "uid" && receiver != "email" {
		fields["receiver"] = []string{a.fieldMessage(r, b, "receiver", "in")}
	}
	title := v.text("title")
	if title == "" {
		fields["title"] = []string{a.fieldMessage(r, b, "title", "required")}
	} else if len([]rune(title)) > 20 {
		fields["title"] = []string{a.fieldMessage(r, b, "title", "max.string", ":max", "20")}
	}
	in := notifications.SendInput{Receiver: receiver, Title: title, Content: v.text("content")}
	switch receiver {
	case "uid":
		uid, err := integerValue(v, "uid")
		if err != nil {
			fields["uid"] = []string{a.fieldMessage(r, b, "uid", "required")}
			break
		}
		in.UID = strconv.FormatInt(uid, 10)
		// The frozen rule is required_if + integer + exists:users in that
		// order, so a well-formed but unknown uid reports `exists`, and the
		// controller's ErrNoTarget branch stays reachable only for races.
		exists, err := a.userExists(r, "uid", uid)
		if err != nil {
			a.serverError(w, r, b)
			return
		}
		if !exists {
			fields["uid"] = []string{a.fieldMessage(r, b, "uid", "exists")}
		}
	case "email":
		email := v.text("email")
		if email == "" {
			fields["email"] = []string{a.fieldMessage(r, b, "email", "required")}
			break
		}
		if address, err := mail.ParseAddress(email); err != nil || address.Address != email {
			fields["email"] = []string{a.fieldMessage(r, b, "email", "email")}
			break
		}
		in.Email = email
		exists, err := a.userExists(r, "email", email)
		if err != nil {
			a.serverError(w, r, b)
			return
		}
		if !exists {
			fields["email"] = []string{a.fieldMessage(r, b, "email", "exists")}
		}
	}
	if len(fields) > 0 {
		fail(fields)
		return
	}
	if err := a.notifications.Send(r.Context(), in); err != nil {
		if errors.Is(err, notifications.ErrNoTarget) {
			message := a.message(r, b, "admin.users.operations.non-existent")
			if jsonRequest {
				a.business(w, r, b, 1, "admin.users.operations.non-existent")
				return
			}
			formError(message)
			return
		}
		a.serverError(w, r, b)
		return
	}
	if jsonRequest {
		http.Redirect(w, r, a.cfg.BaseURL+"/admin", http.StatusFound)
		return
	}
	if err := a.putFlash(r.Context(), b, notificationSentForm, a.message(r, b, "admin.notifications.send.success")); err != nil {
		a.serverError(w, r, b)
		return
	}
	http.Redirect(w, r, a.cfg.BaseURL+"/admin", http.StatusFound)
}

// userExists implements the frozen `exists:users` rule for the notification
// receiver fields.
func (a *App) userExists(r *http.Request, column string, value any) (bool, error) {
	var count int
	if err := a.site.Store.DB.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM "+a.site.Store.Table("users")+" WHERE "+column+"=?", value).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// adminChart returns the frozen 31-day series ending today, grouped by local date.
func (a *App) adminChart(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	location := a.cfg.Location
	if location == nil {
		location = time.UTC
	}
	now := time.Now()
	if a.clock != nil {
		now = a.clock()
	}
	today := now.In(location)
	today = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, location)
	locale := a.locale(r, b)
	labels := make([]string, 0, 31)
	for i := 0; i < 31; i++ {
		day := today.AddDate(0, 0, -(30 - i))
		labels = append(labels, chartDateLabel(day, locale))
	}
	oneMonthAgo := today.AddDate(0, -1, 0)
	series := func(table, column string) ([]int, error) {
		byDate := map[string]int{}
		rows, err := a.site.Store.DB.QueryContext(r.Context(), "SELECT "+column+" FROM "+a.site.Store.Table(table)+" WHERE "+column+" >= ?", oneMonthAgo)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var at time.Time
			if err = rows.Scan(&at); err != nil {
				return nil, err
			}
			byDate[at.In(location).Format("2006-01-02")]++
		}
		if err = rows.Err(); err != nil {
			return nil, err
		}
		counts := make([]int, len(labels))
		for i := 0; i < 31; i++ {
			day := today.AddDate(0, 0, -(30 - i))
			counts[i] = byDate[day.Format("2006-01-02")]
		}
		return counts, nil
	}
	registrations, err := series("users", "register_at")
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	uploads, err := series("textures", "upload_at")
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	messages := r.Context().Value(messagesKey{}).(map[string]any)
	t := func(key string) string {
		value := lookup(messages, key)
		if value == key {
			value = lookup(a.assets.Messages[a.cfg.FallbackLocale], key)
		}
		return value
	}
	jsonResponse(w, http.StatusOK, map[string]any{
		"labels": []string{t("admin.index.user-registration"), t("admin.index.texture-uploads")},
		"xAxis":  labels,
		"data":   [][]int{registrations, uploads},
	})
}

// chartDateLabel follows the frozen Carbon isoFormat('l') locale formats.
func chartDateLabel(day time.Time, locale string) string {
	switch locale {
	case "zh_CN", "zh_TW":
		return day.Format("2006/1/2")
	case "ru_RU":
		return day.Format("2.1.2006")
	case "es_ES":
		return day.Format("2/1/2006")
	default:
		return day.Format("1/2/2006")
	}
}

func (a *App) adminUsersList(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	page := 1
	if parsed, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil {
		page = parsed
	}
	path := a.cfg.BaseURL + strings.TrimPrefix(r.URL.Path, a.basePath)
	value, err := a.usersAdmin.List(r.Context(), page, r.URL.Query().Get("q"), path)
	if err != nil {
		a.searchError(w, r, b, err)
		return
	}
	jsonResponse(w, http.StatusOK, value)
}
