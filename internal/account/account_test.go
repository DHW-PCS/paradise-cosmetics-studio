package account_test

import (
	"context"
	"errors"
	"fmt"
	"html"
	"strconv"

	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/account"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/invitation"
	"paradise-cosmetics-studio/internal/legacy/password"
	"paradise-cosmetics-studio/internal/outbox"
	"paradise-cosmetics-studio/internal/players"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/testsupport"
	"paradise-cosmetics-studio/web"
)

type mailbox struct {
	messages []account.Message
	err      error
}

func (m *mailbox) Send(_ context.Context, message account.Message) error {
	m.messages = append(m.messages, message)
	return m.err
}
func fixture(t *testing.T) (*account.Service, *identity.BrowserSession, *mailbox) {
	t.Helper()
	store, id := testsupport.Database(t, "account-")
	h, _ := password.New("MD5", "")
	id.Passwords = h
	hash, _ := h.Hash("original-password")
	if _, err := store.DB.Exec("UPDATE "+store.Table("users")+" SET password=?", hash); err != nil {
		t.Fatal(err)
	}
	modules := testsupport.Modules(store, id)
	view := &site.Service{Store: store, Identity: id, Location: time.FixedZone("site", 8*3600), OptionSnapshot: map[string]string{}, Modules: modules}
	assets, err := web.Load()
	if err != nil {
		t.Fatal(err)
	}
	box := &mailbox{}
	mail, err := account.NewMail([]byte("synthetic-account-key-32-bytes-minimum"), "http://localhost/skin", "en", view, assets.Messages, box, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s := account.New(store, id, view, mail)
	s.Modules = modules
	b, err := id.Login(t.Context(), "user@example.invalid", "original-password", true, "")
	if err != nil {
		t.Fatal(err)
	}
	return s, b, box
}
func runTogether(t *testing.T, n int, fn func(int) error, expected error) {
	t.Helper()
	var wg sync.WaitGroup
	start := make(chan struct{})
	var successes atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			err := fn(i)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, expected) {
				t.Errorf("unexpected command failure: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful commands=%d, want 1", successes.Load())
	}
}
func TestRegistrationNamespaceQuotaAndAtomicInitialState(t *testing.T) {
	s, _, _ := fixture(t)
	in := account.Registration{Email: "new@example.invalid", PlayerName: "NewPlayer", Password: "new-password", IP: "203.0.113.1", Locale: "en"}
	runTogether(t, 2, func(int) error { _, err := register(t, s, in); return err }, account.ErrEmailUsed)
	var score, players int
	var verified bool
	err := s.Store.DB.QueryRow("SELECT score,verified,(SELECT COUNT(*) FROM "+s.Store.Table("players")+" p WHERE p.uid=u.uid) FROM "+s.Store.Table("users")+" u WHERE email=?", in.Email).Scan(&score, &verified, &players)
	if err != nil || score != 1000 || verified || players != 1 {
		t.Fatalf("registration state score=%d verified=%v players=%d err=%v", score, verified, players, err)
	}
	s.Site.OptionSnapshot["regs_per_ip"] = "1"
	in.Email = "quota@example.invalid"
	in.PlayerName = "QuotaPlayer"
	if _, err = register(t, s, in); !errors.Is(err, account.ErrIPQuota) {
		t.Fatal("IP quota not enforced", err)
	}
	// The eligibility decision reads the authoritative rows inside the
	// registration transaction; the option snapshot no longer decides.
	if _, err = s.Store.DB.Exec("UPDATE "+s.Store.Table("options")+" SET option_value=? WHERE option_name='go_module_installations'", `[{"name":"invitation-codes","version":"1.0"}]`); err != nil {
		t.Fatal(err)
	}
	if err = s.Modules.Enable(t.Context(), adminSession(t, s), "invitation-codes"); err != nil {
		t.Fatal(err)
	}
	// With the consumer connected an enabled module consults the request's
	// code; only the unconnected restricting modules refuse outright.
	if _, err = register(t, s, in); invitation.ErrEmpty == nil || !strings.Contains(invitation.ErrEmpty.Error(), "empty") {
		t.Fatal("consumer registration contract changed", invitation.ErrEmpty)
	}
	// A restricting module without a connected consumer refuses as before.
	if _, err := s.Store.DB.Exec("UPDATE "+s.Store.Table("options")+" SET option_value=? WHERE option_name='go_module_installations'", `[{"name":"disable-registration","version":"1.0"}]`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.DB.Exec("UPDATE "+s.Store.Table("options")+" SET option_value=? WHERE option_name='plugins_enabled'", `[{"name":"invitation-codes","version":"3.1.2"},{"name":"disable-registration","version":"1.0"}]`); err != nil {
		t.Fatal(err)
	}
	in.IP = "203.0.113.2"
	if _, err = register(t, s, in); !errors.Is(err, account.ErrModuleUnavailable) {
		t.Fatal("unconnected restricting module bypassed", err)
	}
	if _, err = s.Store.DB.Exec("UPDATE "+s.Store.Table("options")+" SET option_value=? WHERE option_name='plugins_enabled'", `["invitation-codes"]`); err != nil {
		t.Fatal(err)
	}
	if _, err = register(t, s, in); err != nil {
		t.Fatal("ignored legacy string entry changed policy", err)
	}
}
func TestRegistrationRollbackIncludesChallengeAndTask(t *testing.T) {
	s, _, _ := fixture(t)
	s.Site.OptionSnapshot["require_verification"] = "true"
	if _, err := s.Store.DB.Exec("CREATE TRIGGER reject_mail BEFORE INSERT ON " + s.Store.Table("go_outbox") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic outbox fault'"); err != nil {
		t.Fatal(err)
	}
	_, err := register(t, s, account.Registration{Email: "rollback@example.invalid", PlayerName: "Rollback", Password: "new-password", IP: "203.0.113.9", Locale: "en"})
	if err == nil {
		t.Fatal("injected outbox failure not returned")
	}
	for table, want := range map[string]int{"users": 2, "players": 1, "go_mail_challenges": 0, "go_outbox": 0} {
		var count int
		if err = s.Store.DB.QueryRow("SELECT COUNT(*) FROM " + s.Store.Table(table)).Scan(&count); err != nil || count != want {
			t.Fatalf("partial registration %s count=%d err=%v", table, count, err)
		}
	}
}
func TestSignAtMidnightAndGapAreAtomic(t *testing.T) {
	s, b, _ := fixture(t)
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, s.Site.Location)
	s.Now = func() time.Time { return now }
	s.Award = func(min, max int64) int64 { return min }
	s.Site.OptionSnapshot["sign_after_zero"] = "true"
	s.Site.OptionSnapshot["sign_score"] = "12,12"
	runTogether(t, 4, func(int) error { _, err := s.Sign(t.Context(), b); return err }, account.ErrTooSoon)
	var score int
	if err := s.Store.DB.QueryRow("SELECT score FROM " + s.Store.Table("users") + " WHERE uid=1").Scan(&score); err != nil || score != 83 {
		t.Fatalf("sign score=%d err=%v", score, err)
	}
	s.Site.OptionSnapshot["sign_after_zero"] = "false"
	s.Site.OptionSnapshot["sign_gap_time"] = "24"
	now = now.Add(24*time.Hour - time.Second)
	if _, err := s.Sign(t.Context(), b); !errors.Is(err, account.ErrTooSoon) {
		t.Fatal("gap admitted early", err)
	}
	now = now.Add(time.Second)
	if _, err := s.Sign(t.Context(), b); err != nil {
		t.Fatal("gap boundary rejected", err)
	}
}
func deliverToken(t *testing.T, s *account.Service, box *mailbox) string {
	t.Helper()
	var raw string
	if err := s.Store.DB.QueryRow("SELECT payload FROM " + s.Store.Table("go_outbox") + " WHERE completed_at IS NULL ORDER BY id DESC LIMIT 1").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "example.invalid") || strings.Contains(raw, "Token") {
		t.Fatal("outbox contains plaintext mail payload")
	}
	worked, err := s.Outbox.DeliverOne(t.Context(), map[string]outbox.Handler{account.MailTopic: s.Mail.Handler(s)}, time.Minute)
	if err != nil || !worked || len(box.messages) == 0 {
		t.Fatal("fake delivery failed", err)
	}
	match := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(box.messages[len(box.messages)-1].HTML)
	if len(match) != 2 {
		t.Fatal("mail link missing")
	}
	link, err := url.Parse(html.UnescapeString(match[1]))
	if err != nil {
		t.Fatal(err)
	}
	return link.Query().Get("token")
}
func TestChallengesSingleUseCurrentEmailVersionAndEmptyPasswordRecovery(t *testing.T) {
	s, b, box := fixture(t)
	if _, err := s.Store.DB.Exec("UPDATE " + s.Store.Table("users") + " SET password='' WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Forgot(t.Context(), b.User.Email, "203.0.113.1", "en"); err != nil {
		t.Fatal(err)
	}
	token := deliverToken(t, s, box)
	if _, err := s.InspectChallenge(t.Context(), 1, "reset", token); err != nil {
		t.Fatal("GET consumed challenge", err)
	}
	runTogether(t, 2, func(int) error { return s.ResetPassword(t.Context(), 1, token, "recovered-password") }, account.ErrInvalidChallenge)
	if _, err := s.Identity.Session(t.Context(), b.Token); !errors.Is(err, identity.ErrSession) {
		t.Fatal("reset did not revoke session", err)
	}
	if _, err := s.Identity.Recall(t.Context(), b.Remember); !errors.Is(err, identity.ErrSession) {
		t.Fatal("reset did not revoke remember", err)
	}
	if _, err := s.Identity.Login(t.Context(), b.User.Email, "recovered-password", false, ""); err != nil {
		t.Fatal("empty-password account cannot recover", err)
	}
	if _, err := s.InspectChallenge(t.Context(), 1, "reset", "old-php-signature"); !errors.Is(err, account.ErrInvalidChallenge) {
		t.Fatal("old challenge accepted")
	}
	if err := s.Forgot(t.Context(), b.User.Email, "203.0.113.2", "en"); err != nil {
		t.Fatal(err)
	}
	token = deliverToken(t, s, box)
	if _, err := s.Store.DB.Exec("UPDATE " + s.Store.Table("users") + " SET email='other@example.invalid' WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetPassword(t.Context(), 1, token, "another-password"); !errors.Is(err, account.ErrInvalidChallenge) {
		t.Fatal("old target email accepted", err)
	}
}
func TestProfileAndAdminRevocationPermissions(t *testing.T) {
	s, b, _ := fixture(t)
	if err := s.ChangeProfile(t.Context(), b, "password", "wrong-password", "changed-password"); !errors.Is(err, identity.ErrCredentials) {
		t.Fatal(err)
	}
	if err := s.ChangeProfile(t.Context(), b, "password", "original-password", "changed-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Identity.Session(t.Context(), b.Token); !errors.Is(err, identity.ErrSession) {
		t.Fatal("profile password did not revoke", err)
	}
	admin, err := s.Identity.Login(t.Context(), "admin@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ChangeProfile(t.Context(), admin, "delete", "original-password", ""); !errors.Is(err, account.ErrForbidden) {
		t.Fatal("admin self deletion accepted", err)
	}
	b, err = s.Identity.Login(t.Context(), "user@example.invalid", "changed-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AdminChange(t.Context(), admin, 1, "permission", "-1"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Identity.Session(t.Context(), b.Token); !errors.Is(err, identity.ErrSession) {
		t.Fatal("ban did not revoke", err)
	}
	if err = s.AdminChange(t.Context(), admin, 2, "permission", "0"); !errors.Is(err, account.ErrForbidden) {
		t.Fatal("self permission change accepted", err)
	}
	if err = s.AdminChange(t.Context(), admin, 1, "delete", ""); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.Store.DB.QueryRow("SELECT COUNT(*) FROM " + s.Store.Table("players") + " WHERE uid=1").Scan(&count); err != nil || count != 0 {
		t.Fatal("account delete left players", err)
	}
}

func register(t *testing.T, s *account.Service, in account.Registration) (*identity.BrowserSession, error) {
	t.Helper()
	b, err := s.Identity.Guest(t.Context())
	if err != nil {
		return nil, err
	}
	in.Guest = b.Token
	return s.Register(t.Context(), in)
}

// adminSession logs the seeded permission-2 fixture account in for module
// operations.
func adminSession(t *testing.T, s *account.Service) *identity.BrowserSession {
	t.Helper()
	b, err := s.Identity.Login(t.Context(), "admin@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerificationResendCooldownAndSingleConsumption(t *testing.T) {
	s, b, box := fixture(t)
	s.Site.OptionSnapshot["require_verification"] = "true"
	if _, err := s.Store.DB.Exec("UPDATE " + s.Store.Table("users") + " SET verified=0 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.Now = func() time.Time { return now }
	if err := s.SendVerification(t.Context(), b, "en"); err != nil {
		t.Fatal(err)
	}
	token := deliverToken(t, s, box)
	if err := s.SendVerification(t.Context(), b, "en"); !errors.Is(err, account.ErrTooSoon) {
		t.Fatal("verification cooldown missing", err)
	}
	if err := s.Verify(t.Context(), 1, token, "wrong@example.invalid"); !errors.Is(err, account.ErrEmailMismatch) {
		t.Fatal("wrong verification email accepted", err)
	}
	if _, err := s.InspectChallenge(t.Context(), 1, "verify", token); err != nil {
		t.Fatal("wrong email consumed challenge", err)
	}
	runTogether(t, 2, func(int) error { return s.Verify(t.Context(), 1, token, b.User.Email) }, account.ErrInvalidChallenge)
	if _, err := s.Store.DB.Exec("UPDATE " + s.Store.Table("users") + " SET verified=0 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := s.SendVerification(t.Context(), b, "en"); err != nil {
		t.Fatal(err)
	}
	token = deliverToken(t, s, box)
	now = now.Add(time.Minute)
	if err := s.SendVerification(t.Context(), b, "en"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InspectChallenge(t.Context(), 1, "verify", token); !errors.Is(err, account.ErrInvalidChallenge) {
		t.Fatal("resend retained old token", err)
	}
	token = deliverToken(t, s, box)
	if err := s.Verify(t.Context(), 1, token, b.User.Email); err != nil {
		t.Fatal("replacement token rejected", err)
	}
}
func TestResetFailureRollsBackConsumptionAndRevocation(t *testing.T) {
	s, b, box := fixture(t)
	if err := s.Forgot(t.Context(), b.User.Email, "203.0.113.50", "en"); err != nil {
		t.Fatal(err)
	}
	token := deliverToken(t, s, box)
	if _, err := s.Store.DB.Exec("CREATE TRIGGER reject_password BEFORE UPDATE ON " + s.Store.Table("users") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic password fault'"); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetPassword(t.Context(), 1, token, "replacement-password"); err == nil {
		t.Fatal("injected password failure ignored")
	}
	if _, err := s.InspectChallenge(t.Context(), 1, "reset", token); err != nil {
		t.Fatal("failed reset consumed challenge", err)
	}
	if _, err := s.Identity.Session(t.Context(), b.Token); err != nil {
		t.Fatal("failed reset committed revocation", err)
	}
	if _, err := s.Store.DB.Exec("DROP TRIGGER reject_password"); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetPassword(t.Context(), 1, token, "replacement-password"); err != nil {
		t.Fatal("reset cannot resume after rollback", err)
	}
}
func TestObsoleteMailDoesNotSendAndBannedRecoveryKeepsPermission(t *testing.T) {
	s, _, box := fixture(t)
	if _, err := s.Store.DB.Exec("UPDATE " + s.Store.Table("users") + " SET permission=-1 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Forgot(t.Context(), "user@example.invalid", "203.0.113.51", "en"); err != nil {
		t.Fatal("banned account recovery was restricted", err)
	}
	token := deliverToken(t, s, box)
	if err := s.ResetPassword(t.Context(), 1, token, "replacement-password"); err != nil {
		t.Fatal(err)
	}
	var permission int
	if err := s.Store.DB.QueryRow("SELECT permission FROM " + s.Store.Table("users") + " WHERE uid=1").Scan(&permission); err != nil || permission != -1 {
		t.Fatal("password recovery changed ban", err)
	}
	if err := s.Forgot(t.Context(), "user@example.invalid", "203.0.113.52", "en"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.DB.Exec("DELETE FROM " + s.Store.Table("go_mail_challenges")); err != nil {
		t.Fatal(err)
	}
	before := len(box.messages)
	if worked, err := s.Outbox.DeliverOne(t.Context(), map[string]outbox.Handler{account.MailTopic: s.Mail.Handler(s)}, time.Minute); err != nil || !worked || len(box.messages) != before {
		t.Fatal("obsolete challenge sent mail", err)
	}
}

func TestConcurrentRegistrationPlayerNameAndIPQuota(t *testing.T) {
	s, _, _ := fixture(t)
	runTogether(t, 2, func(i int) error {
		in := account.Registration{Email: fmt.Sprintf("name%d@example.invalid", i), PlayerName: "SharedName", Password: "new-password", IP: fmt.Sprintf("203.0.113.%d", 70+i), Locale: "en"}
		_, err := register(t, s, in)
		return err
	}, account.ErrPlayerUsed)
	s.Site.OptionSnapshot["regs_per_ip"] = "1"
	runTogether(t, 2, func(i int) error {
		in := account.Registration{Email: fmt.Sprintf("ip%d@example.invalid", i), PlayerName: fmt.Sprintf("QuotaName%d", i), Password: "new-password", IP: "203.0.113.80", Locale: "en"}
		_, err := register(t, s, in)
		return err
	}, account.ErrIPQuota)
	s.Site.OptionSnapshot["register_with_player_name"] = "false"
	b, err := register(t, s, account.Registration{Email: "nickname@example.invalid", Nickname: "Nickname", Password: "new-password", IP: "203.0.113.81", Locale: "en"})
	if err != nil {
		t.Fatal(err)
	}
	var players int
	if err := s.Store.DB.QueryRow("SELECT COUNT(*) FROM "+s.Store.Table("players")+" WHERE uid=?", b.User.UID).Scan(&players); err != nil || players != 0 || b.User.Nickname != "Nickname" {
		t.Fatal("nickname registration created an initial player", err)
	}
}
func TestPasswordChangeRacingResetConsumesOnlyCurrentChallenge(t *testing.T) {
	s, b, box := fixture(t)
	if err := s.Forgot(t.Context(), b.User.Email, "203.0.113.90", "en"); err != nil {
		t.Fatal(err)
	}
	token := deliverToken(t, s, box)
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		results <- s.ChangeProfile(t.Context(), b, "password", "original-password", "profile-password")
	}()
	go func() { <-start; results <- s.ResetPassword(t.Context(), 1, token, "reset-password") }()
	close(start)
	successes := 0
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if !errors.Is(err, account.ErrInvalidChallenge) && !errors.Is(err, identity.ErrCredentials) && !errors.Is(err, identity.ErrSession) && !errors.Is(err, identity.ErrStale) {
			t.Fatal("unexpected concurrent password error", err)
		}
	}
	if successes != 1 {
		t.Fatalf("password changes=%d, want 1", successes)
	}
	if _, err := s.Identity.Session(t.Context(), b.Token); !errors.Is(err, identity.ErrSession) {
		t.Fatal("password change retained old session", err)
	}
}

func TestAccountLifecycleKeepsUUIDAndBanTimestamps(t *testing.T) {
	s, _, _ := fixture(t)
	admin, err := s.Identity.Login(t.Context(), "admin@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := players.New(s.Store, s.Identity, s.Site, s.Now)
	var pid int64
	if err = s.Store.DB.QueryRow("SELECT pid FROM " + s.Store.Table("players") + " WHERE uid=1").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err = lifecycle.EnsureUUID(t.Context(), pid); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Store.DB.Exec("UPDATE " + s.Store.Table("players") + " SET last_modified='2020-01-01 00:00:00' WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	if err = s.AdminChange(t.Context(), admin, 1, "permission", "-1"); err != nil {
		t.Fatal(err)
	}
	var modified time.Time
	if err = s.Store.DB.QueryRow("SELECT last_modified FROM "+s.Store.Table("players")+" WHERE pid=?", pid).Scan(&modified); err != nil {
		t.Fatal(err)
	}
	if !modified.After(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("ban did not update player timestamp: %v", modified)
	}
	if err = s.AdminChange(t.Context(), admin, 1, "delete", ""); err != nil {
		t.Fatal(err)
	}
	var players, bindings, uuidRows int
	s.Store.DB.QueryRow("SELECT COUNT(*) FROM " + s.Store.Table("players") + " WHERE uid=1").Scan(&players)
	s.Store.DB.QueryRow("SELECT COUNT(*) FROM "+s.Store.Table("go_uuid_bindings")+" WHERE pid=?", pid).Scan(&bindings)
	s.Store.DB.QueryRow("SELECT COUNT(*) FROM " + s.Store.Table("uuid") + " WHERE name='PlayerOne'").Scan(&uuidRows)
	if players != 0 || bindings != 0 || uuidRows != 1 {
		t.Fatalf("account delete cleanup players=%d bindings=%d uuidRows=%d", players, bindings, uuidRows)
	}
}

func TestAccountDeleteFailureRollsBackPlayers(t *testing.T) {
	s, _, _ := fixture(t)
	admin, err := s.Identity.Login(t.Context(), "admin@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Store.DB.Exec("CREATE TRIGGER reject_player_delete BEFORE DELETE ON " + s.Store.Table("players") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic delete fault'"); err != nil {
		t.Fatal(err)
	}
	if err = s.AdminChange(t.Context(), admin, 1, "delete", ""); err == nil {
		t.Fatal("player delete failure ignored")
	}
	var users, players int
	s.Store.DB.QueryRow("SELECT COUNT(*) FROM " + s.Store.Table("users") + " WHERE uid=1").Scan(&users)
	s.Store.DB.QueryRow("SELECT COUNT(*) FROM " + s.Store.Table("players") + " WHERE uid=1").Scan(&players)
	if users != 1 || players != 1 {
		t.Fatalf("failed account delete left users=%d players=%d", users, players)
	}
}

func TestConcurrentPlayerAddVersusRegistrationName(t *testing.T) {
	s, b, _ := fixture(t)
	s.Site.OptionSnapshot["register_with_player_name"] = "true"
	if _, err := s.Store.DB.Exec("UPDATE " + s.Store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	lifecycle := players.New(s.Store, s.Identity, s.Site, s.Now)
	var wg sync.WaitGroup
	wg.Add(2)
	var addErr, registerErr error
	go func() {
		defer wg.Done()
		_, addErr = lifecycle.Add(t.Context(), b, "RaceName")
	}()
	go func() {
		defer wg.Done()
		_, registerErr = register(t, s, account.Registration{Email: "race@example.invalid", PlayerName: "RaceName", Password: "password-123", IP: "203.0.113.9", Locale: "en"})
	}()
	wg.Wait()
	if (addErr == nil) == (registerErr == nil) {
		t.Fatalf("exactly one creator expected: add=%v register=%v", addErr, registerErr)
	}
	if addErr != nil && !errors.Is(addErr, players.ErrPlayerUsed) {
		t.Fatalf("add error = %v", addErr)
	}
	if registerErr != nil && !errors.Is(registerErr, account.ErrPlayerUsed) {
		t.Fatalf("register error = %v", registerErr)
	}
	var playersCount int
	if err := s.Store.DB.QueryRow("SELECT COUNT(*) FROM " + s.Store.Table("players") + " WHERE name='RaceName'").Scan(&playersCount); err != nil || playersCount != 1 {
		t.Fatalf("player rows for name = %d err=%v", playersCount, err)
	}
}

func TestRenameVersusAccountDelete(t *testing.T) {
	s, b, _ := fixture(t)
	admin, err := s.Identity.Login(t.Context(), "admin@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	var pid int64
	if err = s.Store.DB.QueryRow("SELECT pid FROM " + s.Store.Table("players") + " WHERE uid=1").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	lifecycle := players.New(s.Store, s.Identity, s.Site, s.Now)
	if _, err = lifecycle.EnsureUUID(t.Context(), pid); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	var renameErr, deleteErr error
	go func() {
		defer wg.Done()
		_, _, renameErr = lifecycle.Rename(t.Context(), b, pid, "RaceRenamed", players.Normal)
	}()
	go func() {
		defer wg.Done()
		deleteErr = s.AdminChange(t.Context(), admin, 1, "delete", "")
	}()
	wg.Wait()
	if deleteErr != nil {
		t.Fatalf("account delete failed: %v", deleteErr)
	}
	if renameErr != nil && !errors.Is(renameErr, identity.ErrSession) && !errors.Is(renameErr, players.ErrNotFound) && !errors.Is(renameErr, players.ErrConflict) {
		t.Fatalf("rename error = %v", renameErr)
	}
	var users, playerRows, bindings int
	s.Store.DB.QueryRow("SELECT COUNT(*) FROM " + s.Store.Table("users") + " WHERE uid=1").Scan(&users)
	s.Store.DB.QueryRow("SELECT COUNT(*) FROM " + s.Store.Table("players") + " WHERE uid=1").Scan(&playerRows)
	s.Store.DB.QueryRow("SELECT COUNT(*) FROM "+s.Store.Table("go_uuid_bindings")+" WHERE pid=?", pid).Scan(&bindings)
	if users != 0 || playerRows != 0 || bindings != 0 {
		t.Fatalf("final state users=%d players=%d bindings=%d", users, playerRows, bindings)
	}
}

func enableInvitationModule(t *testing.T, s *account.Service) {
	t.Helper()
	if _, err := s.Store.DB.Exec("UPDATE "+s.Store.Table("options")+" SET option_value=? WHERE option_name='go_module_installations'", `[{"name":"invitation-codes","version":"3.1.2"}]`); err != nil {
		t.Fatal(err)
	}
	if err := s.Modules.Enable(t.Context(), adminSession(t, s), "invitation-codes"); err != nil {
		t.Fatal(err)
	}
}

func seedInvitationCode(t *testing.T, s *account.Service, code string) {
	t.Helper()
	if _, err := s.Store.DB.Exec("INSERT INTO "+s.Store.Table("invitation_codes")+" (code,generated_at) VALUES (?,NOW(6))", code); err != nil {
		t.Fatal(err)
	}
}

func invitationState(t *testing.T, s *account.Service, code string) (usedBy int64, users int) {
	t.Helper()
	if err := s.Store.DB.QueryRow("SELECT used_by FROM "+s.Store.Table("invitation_codes")+" WHERE code=?", code).Scan(&usedBy); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.DB.QueryRow("SELECT COUNT(*) FROM " + s.Store.Table("users")).Scan(&users); err != nil {
		t.Fatal(err)
	}
	return usedBy, users
}

func TestRegistrationConsumesOneSeededRow(t *testing.T) {
	s, _, _ := fixture(t)
	enableInvitationModule(t, s)
	code := strings.Repeat("a", 32)
	seedInvitationCode(t, s, code)
	s.Site.OptionSnapshot["regs_per_ip"] = "500"
	if _, err := register(t, s, account.Registration{Email: "invited@example.invalid", PlayerName: "InvitedPlayer", Password: "new-password", IP: "203.0.113.40", Locale: "en", InvitationCode: code}); err != nil {
		t.Fatal(err)
	}
	usedBy, users := invitationState(t, s, code)
	var invited int64
	if err := s.Store.DB.QueryRow("SELECT uid FROM " + s.Store.Table("users") + " WHERE email='invited@example.invalid'").Scan(&invited); err != nil {
		t.Fatal(err)
	}
	if usedBy != invited {
		t.Fatalf("consumed uid=%d, want %d", usedBy, invited)
	}
	if users != 3 {
		t.Fatalf("users=%d", users)
	}
	// The same code is gone after the membership; a second registration
	// can no longer pass eligibility.
	if _, err := register(t, s, account.Registration{Email: "second@example.invalid", PlayerName: "SecondPlayer", Password: "new-password", IP: "203.0.113.41", Locale: "en", InvitationCode: code}); !errors.Is(err, invitation.ErrUnavailable) {
		t.Fatalf("reused code accepted: %v", err)
	}
	// An enabled module with an empty code fails the registration with the
	// consumer's empty refusal.
	if _, err := register(t, s, account.Registration{Email: "empty@example.invalid", PlayerName: "EmptyPlayer", Password: "new-password", IP: "203.0.113.42", Locale: "en"}); !errors.Is(err, invitation.ErrEmpty) {
		t.Fatalf("empty code accepted: %v", err)
	}
}

func TestRegistrationSameCodeConcurrencyKeepsOneAccount(t *testing.T) {
	s, _, _ := fixture(t)
	enableInvitationModule(t, s)
	code := strings.Repeat("b", 32)
	seedInvitationCode(t, s, code)
	s.Site.OptionSnapshot["regs_per_ip"] = "500"
	runTogether(t, 100, func(i int) error {
		_, err := register(t, s, account.Registration{Email: "same-code-" + strconv.Itoa(i) + "@example.invalid", PlayerName: "Concurrent" + strconv.Itoa(i), Password: "new-password", IP: "203.0.113.50", Locale: "en", InvitationCode: code})
		return err
	}, invitation.ErrUnavailable)
	var successes, qualifications int
	if err := s.Store.DB.QueryRow("SELECT COUNT(*) FROM "+s.Store.Table("invitation_codes")+" WHERE code=? AND used_by <> 0", code).Scan(&successes); err != nil {
		t.Fatal(err)
	}
	if successes != 1 {
		t.Fatalf("consumed rows=%d", successes)
	}
	if err := s.Store.DB.QueryRow("SELECT COUNT(*) FROM " + s.Store.Table("users") + " WHERE ip='203.0.113.50'").Scan(&qualifications); err != nil {
		t.Fatal(err)
	}
	if qualifications != 1 {
		t.Fatalf("accounts created=%d", qualifications)
	}
}

func TestRegistrationRollbackKeepsInvitationAvailable(t *testing.T) {
	s, _, _ := fixture(t)
	enableInvitationModule(t, s)
	s.Site.OptionSnapshot["require_verification"] = "true"
	code := strings.Repeat("c", 32)
	seedInvitationCode(t, s, code)
	s.Site.OptionSnapshot["regs_per_ip"] = "500"
	if _, err := s.Store.DB.Exec("CREATE TRIGGER reject_challenge BEFORE INSERT ON " + s.Store.Table("go_mail_challenges") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic challenge fault'"); err != nil {
		t.Fatal(err)
	}
	if _, err := register(t, s, account.Registration{Email: "rolled@example.invalid", PlayerName: "RollbackPlayer", Password: "new-password", IP: "203.0.113.60", Locale: "en", InvitationCode: code}); err == nil {
		t.Fatal("injected challenge failure ignored")
	}
	usedBy, _ := invitationState(t, s, code)
	if usedBy != 0 {
		t.Fatalf("failed registration consumed the code: uid=%d", usedBy)
	}
	if _, err := s.Store.DB.Exec("DROP TRIGGER reject_challenge"); err != nil {
		t.Fatal(err)
	}
	if _, err := register(t, s, account.Registration{Email: "rolled@example.invalid", PlayerName: "RollbackPlayer", Password: "new-password", IP: "203.0.113.60", Locale: "en", InvitationCode: code}); err != nil {
		t.Fatalf("relaunch after rollback failed: %v", err)
	}
	var relaunched int64
	if err := s.Store.DB.QueryRow("SELECT uid FROM " + s.Store.Table("users") + " WHERE email='rolled@example.invalid'").Scan(&relaunched); err != nil {
		t.Fatal(err)
	}
	usedBy, _ = invitationState(t, s, code)
	if usedBy != relaunched {
		t.Fatalf("relaunch consumed uid=%d, want %d", usedBy, relaunched)
	}
}

func TestDisabledRegistrationModuleIgnoresCodes(t *testing.T) {
	s, _, _ := fixture(t)
	code := strings.Repeat("z", 32)
	seedInvitationCode(t, s, code)
	s.Site.OptionSnapshot["regs_per_ip"] = "500"
	if _, err := register(t, s, account.Registration{Email: "direct@example.invalid", PlayerName: "DirectPlayer", Password: "new-password", IP: "203.0.113.70", Locale: "en", InvitationCode: code}); err != nil {
		t.Fatal(err)
	}
	usedBy, _ := invitationState(t, s, code)
	if usedBy != 0 {
		t.Fatalf("disabled module consumed: uid=%d", usedBy)
	}
}
