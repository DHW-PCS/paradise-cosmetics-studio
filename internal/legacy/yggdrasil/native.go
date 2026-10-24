package yggdrasil

import (
	"blessing-skin-go/internal/legacy/php"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"strings"
)

const NativeClass = `Yggdrasil\Models\Token`

func DecodeNative(data []byte) (php.Value, error) { return php.UnmarshalObjects(data, NativeClass) }
func FromNative(value php.Value, expiry, uid int64) (Token, error) {
	o, ok := value.(*php.Object)
	if !ok || o.Class != NativeClass || o.Properties == nil || len(o.Properties.Entries) != 5 {
		return Token{}, ErrDenied
	}
	a := o.Properties
	t := Token{ExpiresAt: expiry, UID: uid}
	var good bool
	t.Owner, good = a.GetString("owner")
	if !good {
		return t, ErrDenied
	}
	t.ProfileID, good = a.GetString("profileId")
	if !good {
		return t, ErrDenied
	}
	t.CreatedAt, good = a.GetInt("createdAt")
	if !good {
		return t, ErrDenied
	}
	t.ClientToken, good = a.GetString("clientToken")
	if !good {
		return t, ErrDenied
	}
	t.AccessToken, good = a.GetString("accessToken")
	if !good {
		return t, ErrDenied
	}
	return t, nil
}
func (t Token) Native() *php.Object {
	return &php.Object{Class: NativeClass, Properties: php.NewArray().Set("owner", t.Owner).Set("profileId", t.ProfileID).Set("createdAt", t.CreatedAt).Set("clientToken", t.ClientToken).Set("accessToken", t.AccessToken)}
}

type Property struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Signature string `json:"signature,omitempty"`
}
type Profile struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Properties []Property `json:"properties"`
}

// SignedProfile mirrors Profile::serialize, including empty textures as an
// object, slim metadata and SHA-1 RSA signatures for BOTH properties.
func SignedProfile(id, name, skin, cape, model, root string, millis int64, unsigned bool, key *rsa.PrivateKey) (Profile, error) {
	textures := map[string]any{}
	root = strings.TrimRight(root, "/")
	if skin != "" {
		v := map[string]any{"url": root + "/textures/" + skin}
		if model == "slim" {
			v["metadata"] = map[string]string{"model": "slim"}
		}
		textures["SKIN"] = v
	}
	if cape != "" {
		textures["CAPE"] = map[string]string{"url": root + "/textures/" + cape}
	}
	body := map[string]any{"timestamp": millis, "profileId": strings.ReplaceAll(id, "-", ""), "profileName": name, "isPublic": true, "textures": textures}
	if !unsigned {
		if key == nil {
			return Profile{}, ErrDenied
		}
		body["signatureRequired"] = true
	}
	raw, e := json.Marshal(body)
	if e != nil {
		return Profile{}, e
	}
	p := Profile{strings.ReplaceAll(id, "-", ""), name, []Property{{Name: "textures", Value: base64.StdEncoding.EncodeToString(raw)}, {Name: "uploadableTextures", Value: "skin,cape"}}}
	if !unsigned {
		for i := range p.Properties {
			h := sha1.Sum([]byte(p.Properties[i].Value))
			sig, e := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, h[:])
			if e != nil {
				return p, e
			}
			p.Properties[i].Signature = base64.StdEncoding.EncodeToString(sig)
		}
	}
	return p, nil
}
