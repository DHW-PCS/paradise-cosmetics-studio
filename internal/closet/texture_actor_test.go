package closet

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"paradise-cosmetics-studio/internal/identity"
)

// prepareTextureDeleteForTest follows the caller-owned report review lock plan.
// Its actor has only ReportsManagement.ReadWrite, not any Closet scope.
func prepareTextureDeleteForTest(t *testing.T, env fixtureEnv, tx *sql.Tx, actor *fakeActor, tid int64) error {
	t.Helper()
	ctx := t.Context()
	hash, uids, err := env.service.TextureDeleteParticipantsTx(ctx, tx, tid)
	if err != nil {
		return err
	}
	if _, err = env.textures.LockHash(ctx, tx, hash); err != nil {
		return err
	}
	if err = actor.PrepareTx(ctx, tx); err != nil {
		return err
	}
	if err = env.id.LockUsersTx(ctx, tx, append(uids, actor.UID())); err != nil {
		return err
	}
	if _, err = actor.RecheckTx(ctx, tx, identity.ScopeRequirement{AllOf: []string{"ReportsManagement.ReadWrite"}}); err != nil {
		return err
	}
	return env.service.LockTextureDeleteResourcesTx(ctx, tx, tid)
}

func deleteTextureEntryForTest(t *testing.T, env fixtureEnv, browser *identity.BrowserSession, tid int64, entry string) error {
	t.Helper()
	if entry == "browser" {
		return env.service.DeleteTexture(t.Context(), browser, tid)
	}
	actor := actorFor(env.store, browser.User.UID, "ReportsManagement.ReadWrite")
	return env.store.Transaction(t.Context(), func(tx *sql.Tx) error {
		if err := prepareTextureDeleteForTest(t, env, tx, actor, tid); err != nil {
			return err
		}
		err := env.service.DeleteTextureActorTx(t.Context(), tx, actor, tid)
		if actor.rechecks != 1 {
			t.Fatalf("borrowed deletion repeated Actor recheck: %d", actor.rechecks)
		}
		return err
	})
}

func TestLockTextureDeleteResourcesTxNoWrites(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	admin := login(t, env.id, "admin@example.invalid")
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	tid := uploadTexture(t, env, owner, "LockOnlyTexture", "steve", true, 80)
	if err := env.service.Add(t.Context(), admin, tid, "Pick"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.DB.Exec("INSERT INTO "+env.store.Table("players")+" (uid,name,tid_skin,last_modified) VALUES (1,'OwnerLockOnly',?,'2026-01-01 00:00:00'),(2,'AdminLockOnly',?,'2026-01-01 00:00:00')", tid, tid); err != nil {
		t.Fatal(err)
	}
	ownerScore, adminScore := scoreOf(t, env.store, 1), scoreOf(t, env.store, 2)
	actor := actorFor(env.store, 2, "ReportsManagement.ReadWrite")
	err := env.store.Transaction(t.Context(), func(tx *sql.Tx) error {
		if err := prepareTextureDeleteForTest(t, env, tx, actor, tid); err != nil {
			return err
		}
		// Check inside the borrowed transaction so rollback cannot mask writes.
		for _, user := range []struct {
			uid, score int64
			permission int
		}{{1, ownerScore, 0}, {2, adminScore, 2}} {
			var score int64
			var permission int
			if err := tx.QueryRowContext(t.Context(), "SELECT score,permission FROM "+env.store.Table("users")+" WHERE uid=?", user.uid).Scan(&score, &permission); err != nil {
				return err
			}
			if score != user.score || permission != user.permission {
				t.Fatalf("lock-only phase changed user %d: score=%d permission=%d", user.uid, score, permission)
			}
		}
		for _, check := range []struct {
			name, query string
			want        int64
		}{
			{"texture", "SELECT COUNT(*) FROM " + env.store.Table("textures") + " WHERE tid=?", 1},
			{"likes", "SELECT likes FROM " + env.store.Table("textures") + " WHERE tid=?", 2},
			{"closet pivots", "SELECT COUNT(*) FROM " + env.store.Table("user_closet") + " WHERE texture_tid=?", 2},
			{"player references", "SELECT COUNT(*) FROM " + env.store.Table("players") + " WHERE tid_skin=?", 2},
			{"active reward", "SELECT COUNT(*) FROM " + env.store.Table("go_closet_rewards") + " WHERE texture_tid=? AND active=1", 1},
		} {
			var got int64
			if err := tx.QueryRowContext(t.Context(), check.query, tid).Scan(&got); err != nil {
				return err
			}
			if got != check.want {
				t.Fatalf("lock-only phase %s = %d, want %d", check.name, got, check.want)
			}
		}
		var tasks int64
		if err := tx.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+env.store.Table("go_outbox")+" WHERE topic='texture.collect'").Scan(&tasks); err != nil {
			return err
		}
		if tasks != 0 || actor.rechecks != 1 {
			t.Fatalf("lock-only phase tasks=%d Actor rechecks=%d", tasks, actor.rechecks)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeleteTextureActorTxCallerRollback(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	admin := login(t, env.id, "admin@example.invalid")
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	tid := uploadTexture(t, env, owner, "ActorDeleteRollback", "steve", true, 79)
	if err := env.service.Add(t.Context(), admin, tid, "Pick"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.DB.Exec("INSERT INTO "+env.store.Table("players")+" (uid,name,tid_skin,last_modified) VALUES (1,'OwnerDeleteRollback',?,'2026-01-01 00:00:00'),(2,'AdminDeleteRollback',?,'2026-01-01 00:00:00')", tid, tid); err != nil {
		t.Fatal(err)
	}
	var hash string
	if err := env.store.DB.QueryRow("SELECT hash FROM "+env.store.Table("textures")+" WHERE tid=?", tid).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	ownerScore, adminScore := scoreOf(t, env.store, 1), scoreOf(t, env.store, 2)
	actor := actorFor(env.store, 2, "ReportsManagement.ReadWrite")
	fault := errors.New("closet test: caller rolls back after deletion")
	err := env.store.Transaction(t.Context(), func(tx *sql.Tx) error {
		if err := prepareTextureDeleteForTest(t, env, tx, actor, tid); err != nil {
			return err
		}
		if err := env.service.DeleteTextureActorTx(t.Context(), tx, actor, tid); err != nil {
			return err
		}
		var count int64
		if err := tx.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+env.store.Table("textures")+" WHERE tid=?", tid).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatalf("texture still exists before caller rollback: %d", count)
		}
		return fault
	})
	if !errors.Is(err, fault) {
		t.Fatalf("caller rollback err = %v, want injected fault", err)
	}
	if actor.rechecks != 1 {
		t.Fatalf("borrowed deletion repeated Actor recheck: %d", actor.rechecks)
	}
	if scoreOf(t, env.store, 1) != ownerScore || scoreOf(t, env.store, 2) != adminScore {
		t.Fatal("caller rollback retained deletion refunds")
	}
	for _, check := range []struct {
		name, query string
		want        int64
	}{
		{"texture", "SELECT COUNT(*) FROM " + env.store.Table("textures") + " WHERE tid=?", 1},
		{"closet pivots", "SELECT COUNT(*) FROM " + env.store.Table("user_closet") + " WHERE texture_tid=?", 2},
		{"player references", "SELECT COUNT(*) FROM " + env.store.Table("players") + " WHERE tid_skin=?", 2},
		{"active reward", "SELECT COUNT(*) FROM " + env.store.Table("go_closet_rewards") + " WHERE texture_tid=? AND active=1", 1},
	} {
		var got int64
		if err := env.store.DB.QueryRow(check.query, tid).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != check.want {
			t.Fatalf("caller rollback %s = %d, want %d", check.name, got, check.want)
		}
	}
	var tasks int64
	if err := env.store.DB.QueryRow("SELECT COUNT(*) FROM " + env.store.Table("go_outbox") + " WHERE topic='texture.collect'").Scan(&tasks); err != nil {
		t.Fatal(err)
	}
	if tasks != 0 {
		t.Fatalf("caller rollback left collection tasks: %d", tasks)
	}
	if _, err := os.Stat(filepath.Join(env.dir, hash)); err != nil {
		t.Fatalf("caller rollback lost texture file: %v", err)
	}
}
