package media

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type Service struct {
	DB                      *sql.DB
	Prefix, Dir             string
	StorageCost, ClosetCost int64
	Authorize               func(context.Context, *sql.Tx, string) (int64, error)
}
type Upload struct {
	Token, Profile, Slot, Model, Name string
	Data                              []byte
}
type Result struct {
	TID  int64  `json:"tid"`
	Cost int64  `json:"cost"`
	Hash string `json:"hash"`
}

func (s *Service) Upload(ctx context.Context, in Upload) (Result, error) {
	var out Result
	if !regexp.MustCompile(`^[A-Za-z0-9_]*$`).MatchString(s.Prefix) || s.Authorize == nil || s.Dir == "" || s.StorageCost < 0 || s.StorageCost > 1000000 || s.ClosetCost < 0 || s.ClosetCost > 1000000 {
		return out, ErrDenied
	}
	if in.Slot != "skin" && in.Slot != "cape" {
		return out, ErrDenied
	}
	if in.Model != "" && in.Model != "default" && in.Model != "slim" {
		return out, ErrDenied
	}
	if e := os.MkdirAll(s.Dir, 0700); e != nil {
		return out, e
	}
	lock, e := os.OpenFile(filepath.Join(s.Dir, ".writer.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return out, e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); e != nil {
		return out, e
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	uid, e := s.Authorize(ctx, tx, in.Token)
	if e != nil {
		return out, e
	}
	var pid, owner, score int64
	var permission int
	e = tx.QueryRowContext(ctx, "SELECT p.pid,p.uid,u.score,u.permission FROM "+s.Prefix+"players p JOIN "+s.Prefix+"uuid x ON x.name=p.name JOIN "+s.Prefix+"users u ON u.uid=p.uid WHERE x.uuid=? FOR UPDATE", in.Profile).Scan(&pid, &owner, &score, &permission)
	if errors.Is(e, sql.ErrNoRows) {
		return out, ErrDenied
	}
	if e != nil {
		return out, e
	}
	if uid != owner || permission < 0 {
		return out, ErrDenied
	}
	kind := "steve"
	if in.Slot == "cape" {
		kind = "cape"
	} else if in.Model == "slim" {
		kind = "alex"
	}
	meta, e := Inspect(in.Data, kind)
	if e != nil {
		return out, e
	}
	out.Hash = meta.Hash
	var storedType string
	e = tx.QueryRowContext(ctx, "SELECT tid,type FROM "+s.Prefix+"textures WHERE hash=? AND uploader=? ORDER BY tid LIMIT 1 FOR UPDATE", meta.Hash, uid).Scan(&out.TID, &storedType)
	fresh := errors.Is(e, sql.ErrNoRows)
	if e != nil && !fresh {
		return out, e
	}
	if !fresh && storedType != kind {
		return out, ErrDenied
	}
	var inCloset int
	if !fresh {
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Prefix+"user_closet WHERE user_uid=? AND texture_tid=?", uid, out.TID).Scan(&inCloset); e != nil {
			return out, e
		}
	}
	if fresh {
		out.Cost = s.StorageCost*int64(meta.KiB) + s.ClosetCost
	} else if inCloset == 0 {
		out.Cost = s.ClosetCost
	}
	if score < out.Cost {
		return out, ErrDenied
	}
	name := strings.TrimSuffix(filepath.Base(in.Name), ".png")
	if name == "" || len([]rune(name)) > 50 {
		return out, ErrDenied
	}
	// Publish complete immutable bytes before committing a row. An interrupted
	// pre-commit write can leave an orphan, never a committed missing file.
	path := filepath.Join(s.Dir, meta.Hash)
	exists, readErr := os.ReadFile(path)
	if readErr == nil {
		if string(exists) != string(in.Data) {
			return out, ErrDenied
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return out, readErr
	} else {
		f, e := os.CreateTemp(s.Dir, ".prepare-")
		if e != nil {
			return out, e
		}
		temp := f.Name()
		defer os.Remove(temp)
		if _, e = f.Write(in.Data); e != nil {
			f.Close()
			return out, e
		}
		if e = f.Sync(); e != nil {
			f.Close()
			return out, e
		}
		if e = f.Close(); e != nil {
			return out, e
		}
		if e = os.Rename(temp, path); e != nil {
			return out, e
		}
		dir, e := os.Open(s.Dir)
		if e != nil {
			return out, e
		}
		e = dir.Sync()
		dir.Close()
		if e != nil {
			return out, e
		}
	}
	// Defer orphan cleanup on a known rollback; retain bytes on an ambiguous
	// COMMIT outcome, which a reconciler must inspect before deleting anything.
	committed, ambiguous := false, false
	defer func() {
		if !committed && !ambiguous {
			_ = tx.Rollback()
			var n int
			if s.DB.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+s.Prefix+"textures WHERE hash=?", meta.Hash).Scan(&n) == nil && n == 0 {
				_ = os.Remove(path)
			}
		}
	}()
	if fresh {
		r, e := tx.ExecContext(ctx, "INSERT INTO "+s.Prefix+"textures(name,type,hash,size,public,uploader,likes,upload_at) VALUES(?,?,?,?,0,?,1,?)", name, kind, meta.Hash, meta.KiB, uid, time.Now().In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05"))
		if e != nil {
			return out, e
		}
		out.TID, e = r.LastInsertId()
		if e != nil {
			return out, e
		}
	}
	if inCloset == 0 {
		if _, e = tx.ExecContext(ctx, "INSERT INTO "+s.Prefix+"user_closet(user_uid,texture_tid,item_name) VALUES(?,?,?)", uid, out.TID, name); e != nil {
			return out, e
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE "+s.Prefix+"users SET score=score-? WHERE uid=?", out.Cost, uid); e != nil {
		return out, e
	}
	// Slot is selected from the fixed two-value allowlist before interpolation.
	if _, e = tx.ExecContext(ctx, fmt.Sprintf("UPDATE %splayers SET tid_%s=?,last_modified=? WHERE pid=?", s.Prefix, in.Slot), out.TID, time.Now().In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05"), pid); e != nil {
		return out, e
	}
	ambiguous = true
	if e = tx.Commit(); e != nil {
		return out, e
	}
	committed = true
	return out, nil
}
