package httpapp

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReportLifecycleAndNotifications(t *testing.T) {
	options := map[string]string{"reporter_score_modification": "-5", "reporter_reward_score": "10"}
	h, id := appFixtureWithOptions(t, options)
	userCookie, userCSRF := credentials(t, h, false)
	adminCookie, adminCSRF := credentials(t, h, true)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	beforeReport := score(t, id, 1)
	up := uploadRequest(t, h, adminCookie, adminCSRF, "Reported", "steve", "1", pngBytes(t, 64, 64, 81))
	if up.Code != 200 {
		t.Fatalf("upload status=%d body=%s", up.Code, up.Body.String())
	}
	var tid int64
	id.Store.DB.QueryRow("SELECT tid FROM " + id.Store.Table("textures") + " WHERE name='Reported'").Scan(&tid)
	w := request(t, h, "POST", "/skinlib/report", `{"tid":`+itoa(tid)+`,"reason":"inappropriate"}`, userCSRF, userCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("report submit status=%d body=%s", w.Code, w.Body.String())
	}
	if score(t, id, 1) != beforeReport-5 {
		t.Fatalf("report deposit = %d", beforeReport-score(t, id, 1))
	}
	w = request(t, h, "POST", "/skinlib/report", `{"tid":`+itoa(tid)+`,"reason":"again"}`, userCSRF, userCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":1`) {
		t.Fatalf("duplicate report status=%d body=%s", w.Code, w.Body.String())
	}
	var reportID int64
	id.Store.DB.QueryRow("SELECT id FROM " + id.Store.Table("reports")).Scan(&reportID)
	w = request(t, h, "GET", "/user/reports", "", "", userCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "inappropriate") {
		t.Fatalf("user reports page status=%d body=%.300s", w.Code, w.Body.String())
	}
	// The frozen user report page renders reports.links() in a card footer.
	if !strings.Contains(w.Body.String(), `<ul class="pagination">`) || !strings.Contains(w.Body.String(), "pagination.previous") {
		t.Fatalf("user reports page missing paginator: %.400s", w.Body.String())
	}
	w = request(t, h, "GET", "/user/reports/list", "", "", userCookie)
	var tracked map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &tracked) != nil {
		t.Fatalf("user reports json status=%d body=%s", w.Code, w.Body.String())
	}
	if tracked["per_page"] != float64(10) || tracked["total"] != float64(1) {
		t.Fatalf("user reports json paginator=%v", tracked)
	}
	w = request(t, h, "GET", "/admin/reports/list?page=1", "", "", adminCookie)
	var page map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page["per_page"] != float64(9) {
		t.Fatalf("admin reports status=%d body=%s", w.Code, w.Body.String())
	}
	if page["path"] != "http://localhost/skin/admin/reports/list" || page["links"] == nil {
		t.Fatalf("admin reports paginator shape=%v", page)
	}
	// fields: projects report rows to the requested columns.
	w = request(t, h, "GET", "/admin/reports/list?q=fields%3Atid%2Cstatus", "", "", adminCookie)
	var reportProjection map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reportProjection) != nil {
		t.Fatalf("admin reports fields status=%d body=%s", w.Code, w.Body.String())
	}
	rows := reportProjection["data"].([]any)
	if len(rows) > 0 {
		row := rows[0].(map[string]any)
		if len(row) != 2 || row["tid"] == nil || row["status"] == nil {
			t.Fatalf("admin reports fields projection=%v", row)
		}
	}
	// Reports DSL applies the frozen report columns.
	w = request(t, h, "GET", "/admin/reports/list?q=status%3A0&page=1", "", "", adminCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("reports dsl body=%s", w.Body.String())
	}
	// First review deletes the texture, then returns the deposit and pays the award.
	w = request(t, h, "PUT", "/admin/reports/"+itoa(reportID)+"?lang=en", `{"action":"delete"}`, adminCSRF, adminCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":1`) || !strings.Contains(w.Body.String(), "Operated successfully.") {
		t.Fatalf("review status=%d body=%s", w.Code, w.Body.String())
	}
	if score(t, id, 1) != beforeReport+10 {
		t.Fatalf("review accounting = %d, want %d", score(t, id, 1), beforeReport+10)
	}
	var textures int
	id.Store.DB.QueryRow("SELECT COUNT(*) FROM " + id.Store.Table("textures") + " WHERE tid=?").Scan(&textures)
	if textures != 0 {
		t.Fatalf("review did not delete texture: %d", textures)
	}
	// Repeated review does not repeat scoring or deletion.
	before := score(t, id, 1)
	w = request(t, h, "PUT", "/admin/reports/"+itoa(reportID), `{"action":"delete"}`, adminCSRF, adminCookie)
	if w.Code != 200 || score(t, id, 1) != before {
		t.Fatalf("repeated review changed state: %d %s", w.Code, w.Body.String())
	}
}

func TestReviewMissingTextureMessage(t *testing.T) {
	h, id := appFixtureWithOptions(t, map[string]string{"reporter_score_modification": "-5", "reporter_reward_score": "10"})
	cookie, csrf := credentials(t, h, true)
	result, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("reports") + " (tid,uploader,reporter,reason,status,report_at) VALUES (999,2,1,'removed texture',0,NOW())")
	if err != nil {
		t.Fatal(err)
	}
	reportID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	before := score(t, id, 1)
	w := request(t, h, "PUT", "/admin/reports/"+itoa(reportID)+"?lang=en", `{"action":"delete"}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "The requested texture has been deleted.") || score(t, id, 1) != before+5 {
		t.Fatalf("missing texture review status=%d score=%d body=%s", w.Code, score(t, id, 1), w.Body.String())
	}
	w = request(t, h, "PUT", "/admin/reports/"+itoa(reportID)+"?lang=en", `{"action":"delete"}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Operated successfully.") || score(t, id, 1) != before+5 {
		t.Fatalf("repeated review status=%d score=%d body=%s", w.Code, score(t, id, 1), w.Body.String())
	}
}

func TestNotificationsUnreadReadAndSend(t *testing.T) {
	h, id := appFixture(t)
	userCookie, userCSRF := credentials(t, h, false)
	adminCookie, adminCSRF := credentials(t, h, true)
	if _, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("notifications") + " (id,notifiable_type,notifiable_id,data,created_at) VALUES ('n1','App\\\\Models\\\\User',1,'{\"title\":\"Hello\",\"content\":\"**bold**\"}','2026-01-01 00:00:00')"); err != nil {
		t.Fatal(err)
	}
	w := request(t, h, "GET", "/notifications", "", "", userCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"title":"Hello"`) {
		t.Fatalf("unread status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "POST", "/user/notifications/n1", `{}`, userCSRF, userCookie)
	var read map[string]string
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &read) != nil || !strings.Contains(read["content"], "<strong>bold</strong>") {
		t.Fatalf("read status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "POST", "/user/notifications/n1", `{}`, userCSRF, userCookie)
	if w.Code != 404 {
		t.Fatalf("repeat read status=%d", w.Code)
	}
	w = request(t, h, "POST", "/admin/notifications/send", `{"receiver":"all","title":"Notice","content":"hi"}`, adminCSRF, adminCookie)
	if w.Code != 302 {
		t.Fatalf("send status=%d body=%s", w.Code, w.Body.String())
	}
	var count int
	id.Store.DB.QueryRow("SELECT COUNT(*) FROM " + id.Store.Table("notifications")).Scan(&count)
	if count != 3 {
		t.Fatalf("notifications after broadcast = %d", count)
	}
	// exists:users rejects an unknown uid at validation time (frozen rule order),
	// so the JSON client sees the framework 422 rather than code 1.
	w = request(t, h, "POST", "/admin/notifications/send", `{"receiver":"uid","uid":999,"title":"X"}`, adminCSRF, adminCookie)
	if w.Code != 422 || !strings.Contains(w.Body.String(), `"errors":{"uid"`) {
		t.Fatalf("send missing target status=%d body=%s", w.Code, w.Body.String())
	}
}

// TestAdminNotificationFormFlash covers the frozen dashboard widget: validation
// exists both ways, errors.first renders as a danger callout, and
// session_pull('sentResult') renders once as a success callout.
func TestAdminNotificationFormFlash(t *testing.T) {
	h, _ := appFixture(t)
	adminCookie, adminCSRF := credentials(t, h, true)
	form := func(body string, accept string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://localhost/skin/admin/notifications/send", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Accept", accept)
		r.Header.Set("X-CSRF-TOKEN", adminCSRF)
		r.AddCookie(adminCookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := form("_token="+adminCSRF+"&receiver=uid&uid=999&title=Hi", "text/html")
	if w.Code != 302 || w.Header().Get("Location") != "http://localhost/skin/admin" {
		t.Fatalf("invalid uid status=%d location=%s", w.Code, w.Header().Get("Location"))
	}
	page := request(t, h, "GET", "/admin", "", "", adminCookie)
	if !strings.Contains(page.Body.String(), `callout callout-danger`) {
		t.Fatalf("missing error callout: %.400s", page.Body.String())
	}
	again := request(t, h, "GET", "/admin", "", "", adminCookie)
	if strings.Contains(again.Body.String(), `callout callout-danger`) {
		t.Fatal("error callout was not consumed")
	}
	// Unknown email is rejected by exists:users as well.
	w = form("_token="+adminCSRF+"&receiver=email&email=nobody%40example.invalid&title=Hi", "text/html")
	if w.Code != 302 {
		t.Fatalf("invalid email status=%d body=%s", w.Code, w.Body.String())
	}
	emailError := request(t, h, "GET", "/admin", "", "", adminCookie)
	if !strings.Contains(emailError.Body.String(), `callout callout-danger`) {
		t.Fatal("unknown email did not render a danger callout")
	}
	// Success: the dashboard renders the success callout exactly once.
	w = form("_token="+adminCSRF+"&receiver=uid&uid=1&title=Hello", "text/html")
	if w.Code != 302 || w.Header().Get("Location") != "http://localhost/skin/admin" {
		t.Fatalf("send ok status=%d location=%s", w.Code, w.Header().Get("Location"))
	}
	page = request(t, h, "GET", "/admin", "", "", adminCookie)
	if !strings.Contains(page.Body.String(), `callout callout-success`) || !strings.Contains(page.Body.String(), "Sent successfully!") {
		t.Fatalf("missing success callout: %.400s", page.Body.String())
	}
	again = request(t, h, "GET", "/admin", "", "", adminCookie)
	if strings.Contains(again.Body.String(), `callout callout-success`) {
		t.Fatal("success callout was not consumed")
	}
	// JSON clients keep the frozen 422 shape.
	w = request(t, h, "POST", "/admin/notifications/send", `{"receiver":"uid","uid":"abc","title":"Hi"}`, adminCSRF, adminCookie)
	if w.Code != 422 {
		t.Fatalf("json validation status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestAdminUsersDSLAndChart(t *testing.T) {
	h, _ := appFixture(t)
	adminCookie, _ := credentials(t, h, true)
	w := request(t, h, "GET", "/admin/users/list?q=permission%3E%3D2&page=1", "", "", adminCookie)
	var page map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil {
		t.Fatalf("users dsl status=%d body=%s", w.Code, w.Body.String())
	}
	if page["total"] != float64(1) || page["per_page"] != float64(10) {
		t.Fatalf("users dsl paginator %v", page)
	}
	data := page["data"].([]any)
	first := data[0].(map[string]any)
	for _, key := range []string{"uid", "email", "nickname", "avatar", "score", "permission", "ip", "is_dark_mode", "last_sign_at", "register_at", "verified", "locale"} {
		if _, ok := first[key]; !ok {
			t.Fatalf("user json missing %q: %v", key, first)
		}
	}
	// The paginator must carry every Laravel key, addressed without the query
	// string (the frozen controllers never call withQueryString()).
	for _, key := range []string{"first_page_url", "last_page_url", "next_page_url", "prev_page_url", "path", "links", "from", "to"} {
		if _, ok := page[key]; !ok {
			t.Fatalf("users paginator missing %q: %v", key, page)
		}
	}
	if page["path"] != "http://localhost/skin/admin/users/list" {
		t.Fatalf("users paginator path=%v", page["path"])
	}
	links := page["links"].([]any)
	if len(links) != 3 || links[0].(map[string]any)["label"] != "pagination.previous" {
		t.Fatalf("users paginator links=%v", links)
	}
	// fields: projects the row to the requested columns only.
	w = request(t, h, "GET", "/admin/users/list?q=fields%3Auid%2Cscore", "", "", adminCookie)
	var projected map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &projected) != nil {
		t.Fatalf("users fields status=%d body=%s", w.Code, w.Body.String())
	}
	row := projected["data"].([]any)[0].(map[string]any)
	if len(row) != 2 || row["uid"] == nil || row["score"] == nil {
		t.Fatalf("users fields projection=%v", row)
	}
	w = request(t, h, "GET", "/admin/users/list?q=notAKey%3A1", "", "", adminCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"total":2`) {
		t.Fatalf("invalid dsl fallback body=%s", w.Body.String())
	}
	w = request(t, h, "GET", "/admin/chart", "", "", adminCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"xAxis"`) || !strings.Contains(w.Body.String(), `"labels"`) {
		t.Fatalf("chart status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestChartUsesIndividualDates(t *testing.T) {
	h, id := appFixture(t)
	cookie, _ := credentials(t, h, true)
	today := time.Now().UTC()
	today = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	for uid, day := range map[int]time.Time{1: today, 2: today.AddDate(0, 0, -7)} {
		if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("users")+" SET register_at=? WHERE uid=?", day, uid); err != nil {
			t.Fatal(err)
		}
	}
	w := request(t, h, "GET", "/admin/chart?lang=en", "", "", cookie)
	var chart struct {
		XAxis []string `json:"xAxis"`
		Data  [][]int  `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &chart); err != nil {
		t.Fatal(err)
	}
	if len(chart.XAxis) != 31 || len(chart.Data) != 2 || len(chart.Data[0]) != 31 {
		t.Fatal("invalid chart shape")
	}
	if chart.XAxis[0] != chartDateLabel(today.AddDate(0, 0, -30), "en") || chart.XAxis[30] != chartDateLabel(today, "en") {
		t.Fatal("chart window shifted")
	}
	for i, count := range chart.Data[0] {
		want := 0
		if i == 23 || i == 30 {
			want = 1
		}
		if count != want {
			t.Fatalf("date index %d count %d want %d", i, count, want)
		}
	}
}

func TestChartDateLocaleMatchesFrozenCarbon(t *testing.T) {
	day := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	// PHP 8.1.34 / frozen Carbon isoFormat('l'), recorded in chart-php.json.
	for locale, want := range map[string]string{"zh_CN": "2026/1/2", "zh_TW": "2026/1/2", "en": "1/2/2026", "ru_RU": "2.1.2026", "es_ES": "2/1/2026"} {
		if got := chartDateLabel(day, locale); got != want {
			t.Fatalf("locale %s: %s want %s", locale, got, want)
		}
	}
}
