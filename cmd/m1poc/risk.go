package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"paradise-cosmetics-studio/internal/legacy/buildcompat"
	"paradise-cosmetics-studio/internal/legacy/cache"
	"paradise-cosmetics-studio/internal/legacy/laravel"
	"paradise-cosmetics-studio/internal/legacy/links"
	"paradise-cosmetics-studio/internal/legacy/media"
	"paradise-cosmetics-studio/internal/legacy/passport"
	"paradise-cosmetics-studio/internal/legacy/password"
	"paradise-cosmetics-studio/internal/legacy/registration"
	"paradise-cosmetics-studio/internal/legacy/revocation"
	"paradise-cosmetics-studio/internal/legacy/rules"
	"paradise-cosmetics-studio/internal/legacy/users"
	"paradise-cosmetics-studio/internal/legacy/yggdrasil"
	"regexp"
	"strings"
	"time"
)

// Risk requests travel over stdin; credentials are never command arguments or
// emitted by errors. This command is only the isolated M1 experiment boundary.
type riskRequest struct {
	Translations                                                                                                                               map[string]string
	Domain, Action                                                                                                                             string
	Token                                                                                                                                      yggdrasil.Token
	Raw, Client, Profile, Name, Owner, Server, IP, Key, AppKey, BasePath, URL, Kind, Identity, Password, Path, Data, Mode, Rule, Custom, Value string
	UID, Expiry, Now, ValidTTL, RefreshTTL, StorageCost, ClosetCost                                                                            int64
	Size, Limit                                                                                                                                int
	AllowLegacy, Unsigned                                                                                                                      bool
	Join                                                                                                                                       yggdrasil.Join
	Registration                                                                                                                               registration.Input
	Page                                                                                                                                       buildcompat.CodesPage
	Entries                                                                                                                                    []buildcompat.Entry
	Routes                                                                                                                                     map[string]string
	Extra                                                                                                                                      any
}

func cmdRisk(args []string) error {
	fs := flag.NewFlagSet("risk", flag.ContinueOnError)
	dsn := fs.String("dsn", os.Getenv("M1POC_DSN"), "isolated MySQL DSN")
	prefix := fs.String("prefix", "", "table prefix")
	addr := fs.String("addr", "", "serve PUT upload prototype")
	if e := fs.Parse(args); e != nil {
		return e
	}
	var in riskRequest
	if e := json.NewDecoder(io.LimitReader(os.Stdin, 32<<20)).Decode(&in); e != nil {
		return errors.New("risk: invalid request")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_]*$`).MatchString(*prefix) {
		return errors.New("risk: invalid prefix")
	}
	needsDB := in.Domain == "ygg" || in.Domain == "registration" || in.Domain == "state" || (in.Domain == "links" && in.Action != "verify") || (in.Domain == "media" && (in.Action == "upload" || in.Action == "serve"))
	if needsDB && *dsn == "" {
		return errors.New("risk: isolated DB required")
	}
	var repo *users.Repo
	var e error
	if *dsn != "" {
		repo, e = users.Open(*dsn, *prefix)
		if e != nil {
			return errors.New("risk: database unavailable")
		}
		defer repo.Close()
	}
	var db *sql.DB
	if repo != nil {
		db = repo.DB()
	}
	now := func() time.Time {
		if in.Now > 0 {
			return time.Unix(in.Now, 0)
		}
		return time.Now()
	}
	if in.ValidTTL == 0 {
		in.ValidTTL = 259200
	}
	if in.RefreshTTL == 0 {
		in.RefreshTTL = 604800
	}
	if in.Limit == 0 {
		in.Limit = 10
	}
	store := &yggdrasil.Store{DB: db, Prefix: *prefix, Key: []byte(in.Key), ValidTTL: in.ValidTTL, RefreshTTL: in.RefreshTTL, Limit: in.Limit, Now: now}
	ctx := context.Background()
	var result any
	e = errors.New("unknown action")
	switch in.Domain {
	case "ygg":
		if db == nil {
			return errors.New("risk: isolated DB required")
		}
		switch in.Action {
		case "setup":
			e = store.Setup(ctx)
		case "import":
			e = store.Import(ctx, in.Token)
		case "import-cache":
			var c *cache.Store
			c, e = cache.NewStore(in.Path, "")
			if e != nil {
				break
			}
			c.Decode = yggdrasil.DecodeNative
			c.ReadOnly = true
			var v any
			var exp int64
			var ok bool
			v, exp, ok, e = c.GetWithExpiry("yggdrasil-token-" + in.Raw)
			if e != nil || !ok {
				e = yggdrasil.ErrDenied
				break
			}
			var t yggdrasil.Token
			t, e = yggdrasil.FromNative(v, exp, in.UID)
			if e == nil {
				e = store.Import(ctx, t)
				result = t
			}
		case "allocate":
			result, e = store.Allocate(ctx, in.Name, in.Kind)
		case "issue":
			result, e = store.Issue(ctx, in.UID, in.Owner, in.Profile, in.Client)
		case "validate":
			result, e = store.Validate(ctx, in.Raw, in.Client)
		case "refresh":
			result, e = store.Refresh(ctx, in.Raw, in.Client, in.Profile, in.Name)
		case "revoke":
			e = store.Revoke(ctx, in.Raw)
		case "signout-auth":
			h, err := password.New("BCRYPT", "")
			if err != nil {
				e = err
				break
			}
			e = store.SignoutCredentials(ctx, repo, h, in.Owner, in.Password, in.AllowLegacy)
		case "signout":
			e = store.Signout(ctx, in.UID)
		case "join":
			e = store.Join(ctx, in.Raw, in.Profile, in.Server, in.IP)
		case "import-join":
			e = store.ImportJoin(ctx, in.Server, in.Join, in.AllowLegacy)
		case "has-joined":
			result, e = store.HasJoined(ctx, in.Server, in.Name, in.IP)
		case "profile":
			key, err := passport.LoadPrivateKey(in.Path)
			if err != nil {
				e = err
				break
			}
			result, e = yggdrasil.SignedProfile(in.Profile, in.Name, in.Value, in.Data, in.Mode, in.Owner, in.Expiry, in.Unsigned, key)
		default:
			e = errors.New("unknown action")
		}
	case "links":
		l := links.Ledger{DB: db, Prefix: *prefix, Key: in.AppKey, BasePath: in.BasePath, Now: now}
		switch in.Action {
		case "verify":
			e = links.Verify(in.URL, in.AppKey, in.BasePath, now())
		case "setup":
			e = l.Setup(ctx)
		case "observe":
			e = l.Observe(ctx, in.URL, in.Kind, in.Identity, in.UID, in.Expiry)
		case "consume":
			e = l.Consume(ctx, in.URL, in.Kind, in.Identity, in.UID)
		case "reset":
			// Lock order: Yggdrasil writer, users, link claim. ConsumeReset
			// applies the global lock before touching the account row.
			var email, hash string
			e = db.QueryRowContext(ctx, "SELECT email,password FROM "+*prefix+"users WHERE uid=?", in.UID).Scan(&email, &hash)
			if e != nil {
				break
			}
			e = l.ConsumeReset(ctx, in.URL, links.Identity(email, hash), in.UID, store.LockTx, func(tx *sql.Tx) error {
				return registration.ChangePassword(ctx, tx, *prefix, in.UID, in.Password, laravel.ParseAppKey(in.AppKey))
			})
		default:
			e = errors.New("unknown action")
		}
	case "registration":
		s := registration.Service{DB: db, Prefix: *prefix, InitialScore: 100, FreePlayer: true, Now: now}
		if in.Action == "setup" {
			e = s.Setup(ctx)
			if e == nil {
				e = revocation.New(db, *prefix).EnsureSchema(ctx)
			}
		} else if in.Action == "register" {
			result, e = s.Register(ctx, in.Registration)
		} else {
			e = errors.New("unknown action")
		}
	case "state":
		switch in.Action {
		case "setup":
			e = registration.SetupOutbox(ctx, db, *prefix)
		case "enqueue", "delete-player":
			var tx *sql.Tx
			tx, e = db.BeginTx(ctx, nil)
			if e != nil {
				break
			}
			defer tx.Rollback()
			var uid int64
			uid, e = store.AuthorizeTx(ctx, tx, in.Raw)
			if e != nil {
				break
			}
			if in.Action == "enqueue" {
				e = registration.Enqueue(ctx, tx, *prefix, uid, in.Value)
			} else {
				e = registration.DeletePlayer(ctx, tx, *prefix, uid, int64(in.Size))
			}
			if e == nil {
				e = tx.Commit()
			}
		default:
			e = errors.New("unknown action")
		}
	case "media":
		data, err := base64.StdEncoding.DecodeString(in.Data)
		if err != nil {
			e = err
			break
		}
		switch in.Action {
		case "inspect":
			result, e = media.Inspect(data, in.Kind)
		case "render":
			var b []byte
			b, e = (media.Renderer{Executable: "php", Script: "/tools/m1_render_bridge.php"}).Render(ctx, data, in.Kind, in.Mode, in.Size)
			if e == nil {
				result = base64.StdEncoding.EncodeToString(b)
			}
		case "upload":
			var r media.Result
			r, e = (&media.Service{DB: db, Prefix: *prefix, Dir: in.Path, StorageCost: in.StorageCost, ClosetCost: in.ClosetCost, Authorize: store.AuthorizeTx}).Upload(ctx, media.Upload{Token: in.Raw, Profile: in.Profile, Slot: in.Kind, Model: in.Mode, Name: in.Name, Data: data})
			result = r
		case "serve":
			if *addr == "" {
				return errors.New("risk: --addr required")
			}
			svc := &media.Service{DB: db, Prefix: *prefix, Dir: in.Path, StorageCost: in.StorageCost, ClosetCost: in.ClosetCost, Authorize: store.AuthorizeTx}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					p := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
					if len(p) != 2 || !strings.HasSuffix(p[1], ".png") {
						w.WriteHeader(404)
						return
					}
					b, status, err := media.Legacy(r.Context(), db, *prefix, in.Path, strings.TrimSuffix(p[1], ".png"), p[0])
					if err != nil {
						w.WriteHeader(500)
						return
					}
					if status == 200 {
						w.Header().Set("Content-Type", "image/png")
					}
					w.WriteHeader(status)
					_, _ = w.Write(b)
					return
				}
				if r.Method != "PUT" {
					w.WriteHeader(405)
					return
				}
				p := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
				if len(p) != 2 || (p[1] != "skin" && p[1] != "cape") {
					w.WriteHeader(404)
					return
				}
				raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				if _, err := store.Validate(r.Context(), raw, ""); err != nil {
					w.WriteHeader(403)
					return
				}
				b, model, name, err := media.Multipart(r)
				if err != nil {
					w.WriteHeader(400)
					return
				}
				_, err = svc.Upload(r.Context(), media.Upload{Token: raw, Profile: p[0], Slot: p[1], Model: model, Name: name, Data: b})
				if err != nil {
					w.WriteHeader(403)
					return
				}
				w.WriteHeader(204)
			})
			server := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, MaxHeaderBytes: 16 << 10}
			return server.ListenAndServe()
		}
	case "build":
		switch in.Action {
		case "codes":
			result, e = buildcompat.RenderCodes(in.Page, func(s string) string {
				if v, ok := in.Translations[s]; ok {
					return v
				}
				return s
			})
		case "extra":
			result, e = buildcompat.Extra(in.Extra)
		case "fragments":
			result, e = buildcompat.Fragments(in.Entries, in.BasePath)
		case "routes":
			result, e = buildcompat.Routes(in.Routes)
		}
	case "rules":
		result, e = rules.MatchPlayer(in.Rule, in.Custom, in.Value)
	default:
		e = errors.New("unknown domain")
	}
	// Keep diagnostic payloads out of ordinary errors and reports.
	response := map[string]any{"ok": e == nil, "result": result}
	if e != nil {
		switch {
		case errors.Is(e, links.ErrChallenge):
			response["error"] = "new_challenge"
		case errors.Is(e, yggdrasil.ErrDenied) || errors.Is(e, links.ErrDenied) || errors.Is(e, registration.ErrDenied) || errors.Is(e, media.ErrDenied):
			response["error"] = "denied"
		default:
			response["error"] = "operation_failed"
		}
	}
	var out bytes.Buffer
	if err := json.NewEncoder(&out).Encode(response); err != nil {
		return fmt.Errorf("risk: response encoding failed")
	}
	_, e = os.Stdout.Write(out.Bytes())
	return e
}
