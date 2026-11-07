package yggdrasil

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var errProfileNotFound = errors.New("yggdrasil: profile not found")

// discovered is the unlocked discovery result for one profile: who owns
// it and which binding names it. Locking reads re-verify every field.
type discovered struct {
	PID        int64
	UID        int64
	Name       string
	UUIDHex    string
	UUIDDashed string
}

func (s *Service) discoverByUUID(ctx context.Context, id string) (*discovered, error) {
	hex, ok := normalizeUUIDHex(id)
	if !ok {
		return nil, errProfileNotFound
	}
	d := &discovered{}
	var dashed string
	err := s.Store.DB.QueryRowContext(ctx, "SELECT p.pid,p.uid,p.name,b.uuid FROM "+s.Store.Table("players")+" p JOIN "+s.Store.Table("go_uuid_bindings")+" b ON b.pid=p.pid WHERE b.uuid=?", hex).Scan(&d.PID, &d.UID, &d.Name, &d.UUIDHex)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errProfileNotFound
	}
	if err != nil {
		return nil, err
	}
	dashed, ok = hexToDashed(d.UUIDHex)
	if !ok {
		return nil, errors.New("yggdrasil: stored player binding is malformed")
	}
	d.UUIDDashed = dashed
	return d, nil
}

func (s *Service) discoverByName(ctx context.Context, name string) (*discovered, error) {
	d := &discovered{}
	err := s.Store.DB.QueryRowContext(ctx, "SELECT p.pid,p.uid,p.name,b.uuid FROM "+s.Store.Table("players")+" p JOIN "+s.Store.Table("go_uuid_bindings")+" b ON b.pid=p.pid WHERE p.name=?", name).Scan(&d.PID, &d.UID, &d.Name, &d.UUIDHex)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errProfileNotFound
	}
	if err != nil {
		return nil, err
	}
	dashed, ok := hexToDashed(d.UUIDHex)
	if !ok {
		return nil, errors.New("yggdrasil: stored player binding is malformed")
	}
	d.UUIDDashed = dashed
	return d, nil
}

// Property is one serialized profile property.
type Property struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Signature string `json:"signature,omitempty"`
}

// SerializedProfile is the protocol profile document. ID is hex form
// (legacy str_replace of dashes); JSON is the exact response body for
// batch4 to write.
type SerializedProfile struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Properties []Property `json:"properties"`
	JSON       string     `json:"-"`
}

func (s *Service) textureHashTypeTx(ctx context.Context, tx *sql.Tx, tid int64) (string, string, error) {
	if tid == 0 {
		return "", "", nil
	}
	var hash, kind string
	err := tx.QueryRowContext(ctx, "SELECT hash,type FROM "+s.Store.Table("textures")+" WHERE tid=?", tid).Scan(&hash, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	return hash, kind, err
}

type texturesPayload struct {
	Timestamp         int64          `json:"timestamp"`
	ProfileID         string         `json:"profileId"`
	ProfileName       string         `json:"profileName"`
	IsPublic          bool           `json:"isPublic"`
	Textures          map[string]any `json:"textures"`
	SignatureRequired bool           `json:"signatureRequired,omitempty"`
}

type skinEntry struct {
	URL      string `json:"url"`
	Metadata any    `json:"metadata,omitempty"`
}

type modelMeta struct {
	Model string `json:"model"`
}

func marshalUnescaped(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// buildSerialized constructs the profile document. signed=true requires
// a parseable private key and adds signatureRequired plus one RSA-SHA1
// signature per property value. site_url is the texture URL root: legacy
// forces the root URL from the site_url option before building texture
// URLs.
func (s *Service) buildSerialized(uuidHex, name, skinHash, capeHash, model string, opts map[string]any, now time.Time, signed bool) (*SerializedProfile, error) {
	root := ""
	if raw, present := optionPresent(opts, "site_url"); present {
		root = strings.TrimRight(optionString(raw, present), "/")
	}
	textures := map[string]any{}
	if skinHash != "" {
		entry := skinEntry{URL: textureURL(root, skinHash)}
		if model == "slim" {
			entry.Metadata = modelMeta{Model: "slim"}
		}
		textures["SKIN"] = entry
	}
	if capeHash != "" {
		textures["CAPE"] = skinEntry{URL: textureURL(root, capeHash)}
	}
	payload := texturesPayload{
		Timestamp:   now.UnixMilli(),
		ProfileID:   uuidHex,
		ProfileName: name,
		IsPublic:    true,
		Textures:    textures,
	}
	var key *rsa.PrivateKey
	if signed {
		// Legacy Profile::serialize only requires a parseable private
		// key (openssl_pkey_get_private); the 4096-bit tier applies
		// solely to the hello/publickeys export entry point.
		raw, present := optionPresent(opts, "ygg_private_key")
		loaded, apiErr := ParsePrivateKey(optionString(raw, present))
		if apiErr != nil {
			return nil, apiErr
		}
		key = loaded
		payload.SignatureRequired = true
	}
	rawPayload, err := marshalUnescaped(payload)
	if err != nil {
		return nil, err
	}
	doc := &SerializedProfile{
		ID:   uuidHex,
		Name: name,
		Properties: []Property{
			{Name: "textures", Value: base64.StdEncoding.EncodeToString(rawPayload)},
			{Name: "uploadableTextures", Value: "skin,cape"},
		},
	}
	if signed {
		for i := range doc.Properties {
			sum := sha1.Sum([]byte(doc.Properties[i].Value))
			sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum[:])
			if err != nil {
				return nil, err
			}
			doc.Properties[i].Signature = base64.StdEncoding.EncodeToString(sig)
		}
	}
	rawDoc, err := marshalUnescaped(doc)
	if err != nil {
		return nil, err
	}
	doc.JSON = string(rawDoc)
	return doc, nil
}

func textureURL(root, hash string) string {
	if root == "" {
		return "textures/" + hash
	}
	return root + "/textures/" + hash
}

// GetProfileByUUID returns the profile document for a dashed or hex UUID,
// or (nil, false, nil) for the legacy 204. signed=false is the default
// unsigned form; signed=true mirrors serialize(false) with signatures.
func (s *Service) GetProfileByUUID(ctx context.Context, id string, signed bool) (*SerializedProfile, bool, error) {
	disc, err := s.discoverByUUID(ctx, id)
	if err != nil {
		if errors.Is(err, errProfileNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	now := s.now()
	var doc *SerializedProfile
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err := s.lockModuleState(ctx, tx); err != nil {
			return err
		}
		var owner int64
		var name string
		var tidSkin, tidCape int64
		if err := tx.QueryRowContext(ctx, "SELECT uid,name,tid_skin,tid_cape FROM "+s.Store.Table("players")+" WHERE pid=? FOR UPDATE", disc.PID).Scan(&owner, &name, &tidSkin, &tidCape); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		binding, err := s.lockBindingTx(ctx, tx, disc.PID)
		if err != nil {
			return err
		}
		if binding == nil || binding.UUIDHex != disc.UUIDHex {
			return nil
		}
		skinHash, skinType, err := s.textureHashTypeTx(ctx, tx, tidSkin)
		if err != nil {
			return err
		}
		capeHash, _, err := s.textureHashTypeTx(ctx, tx, tidCape)
		if err != nil {
			return err
		}
		model := "default"
		if skinType != "" && skinType != "steve" {
			model = "slim"
		}
		opts, err := s.opts.load(ctx)
		if err != nil {
			return err
		}
		built, err := s.buildSerialized(binding.UUIDHex, name, skinHash, capeHash, model, opts, now, signed)
		if err != nil {
			return err
		}
		doc = built
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if doc == nil {
		return nil, false, nil
	}
	return doc, true, nil
}

// SearchMultipleProfiles implements the batch profile query. Names are
// deduplicated preserving first occurrence; the count is checked against
// ygg_search_profile_max with the frozen legacy comparison (see
// searchLimitExceeded). Missing players are skipped and an empty result
// is an empty slice, never nil.
func (s *Service) SearchMultipleProfiles(ctx context.Context, names []string) ([]Profile, error) {
	seen := map[string]bool{}
	var unique []string
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			unique = append(unique, n)
		}
	}
	opts, err := s.opts.load(ctx)
	if err != nil {
		return nil, err
	}
	raw, present := optionPresent(opts, "ygg_search_profile_max")
	if searchLimitExceeded(len(unique), raw, present) {
		return nil, QueryMaxError(optionText(raw, present))
	}
	out := []Profile{}
	for _, name := range unique {
		disc, err := s.discoverByName(ctx, name)
		if errors.Is(err, errProfileNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Profile{ID: disc.UUIDHex, Name: disc.Name})
	}
	return out, nil
}

// SearchSingleProfile returns one profile by exact player name, or
// (nil, false, nil) for the legacy 204.
func (s *Service) SearchSingleProfile(ctx context.Context, username string) (*Profile, bool, error) {
	disc, err := s.discoverByName(ctx, username)
	if err != nil {
		if errors.Is(err, errProfileNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return &Profile{ID: disc.UUIDHex, Name: disc.Name}, true, nil
}

// searchLimitExceeded mirrors `count($names) > option(...)` without a
// cast. An empty request never exceeds. A missing/null option behaves
// as 0, so any non-empty request exceeds. Numeric values compare
// numerically; a non-numeric string compares the decimal count string
// lexicographically, matching PHP 8 int/string comparison.
func searchLimitExceeded(count int, raw any, present bool) bool {
	if count == 0 {
		return false
	}
	if !present || raw == nil {
		return count > 0
	}
	switch t := raw.(type) {
	case bool:
		if t {
			return count > 1
		}
		return count > 0
	case string:
		if _, err := parseDecimal(t); err != nil {
			return intToString(int64(count)) > t
		}
		return int64(count) > optionInt(raw, present)
	default:
		return int64(count) > optionInt(raw, present)
	}
}

// optionText renders an option for the query-max message.
func optionText(raw any, present bool) string {
	if !present || raw == nil {
		return ""
	}
	if text, ok := raw.(string); ok {
		return text
	}
	if b, ok := raw.(bool); ok {
		if b {
			return "1"
		}
		return "0"
	}
	return intToString(optionInt(raw, present))
}
