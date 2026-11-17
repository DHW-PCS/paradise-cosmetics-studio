package account

import (
	"context"
	"crypto/cipher"
	"database/sql"
	"encoding/json"
	"errors"

	"paradise-cosmetics-studio/internal/database"
)

// legacyMailBrandAAD is the persisted pre-rebrand outbox label. Only this
// offline migration may read it; the runtime cipher rejects v1 envelopes.
const legacyMailBrandAAD = "blessing-skin/account-mail/v1"

var errMailBrandMigration = errors.New("account: account mail brand migration failed")

// MigrateMailBrand rewrites every queued account-mail payload from v1 to v2.
// The caller holds the deployment exclusive lock. This function converts
// account-mail rows in one transaction without changing delivery state.
func MigrateMailBrand(ctx context.Context, store *database.Store, key []byte) error {
	legacy, err := mailCipherForLabel(key, legacyMailBrandAAD)
	if err != nil {
		return errMailBrandMigration
	}
	current, err := mailCipher(key)
	if err != nil {
		return errMailBrandMigration
	}

	type queuedPayload struct {
		id      int64
		payload json.RawMessage
	}
	err = store.Transaction(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT id,payload FROM "+store.Table("go_outbox")+" WHERE topic=? ORDER BY id FOR UPDATE", MailTopic)
		if err != nil {
			return errMailBrandMigration
		}
		var queued []queuedPayload
		for rows.Next() {
			var item queuedPayload
			if err = rows.Scan(&item.id, &item.payload); err != nil {
				rows.Close()
				return errMailBrandMigration
			}
			queued = append(queued, item)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return errMailBrandMigration
		}
		// The connection must not keep the SELECT open while issuing UPDATEs.
		if err = rows.Close(); err != nil {
			return errMailBrandMigration
		}

		for _, item := range queued {
			payload, changed, err := migrateMailBrandPayload(legacy, current, item.payload)
			if err != nil {
				return errMailBrandMigration
			}
			if !changed {
				continue
			}
			result, err := tx.ExecContext(ctx, "UPDATE "+store.Table("go_outbox")+" SET payload=? WHERE id=? AND topic=?", []byte(payload), item.id, MailTopic)
			if err != nil {
				return errMailBrandMigration
			}
			affected, err := result.RowsAffected()
			if err != nil || affected != 1 {
				return errMailBrandMigration
			}
		}
		return nil
	})
	if err != nil {
		return errMailBrandMigration
	}
	return nil
}

// migrateMailBrandPayload is the pure per-row transformation. It returns the
// original bytes for an already-current envelope, and reseals the exact
// decrypted body bytes for a legacy envelope.
func migrateMailBrandPayload(legacy, current cipher.AEAD, raw json.RawMessage) (json.RawMessage, bool, error) {
	var envelope sealedMail
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, false, errMailBrandMigration
	}
	switch envelope.Version {
	case 1:
		body, err := openMailBody(legacy, 1, legacyMailBrandAAD, raw)
		if err != nil {
			return nil, false, errMailBrandMigration
		}
		if _, err = decodeMailPayload(body); err != nil {
			return nil, false, errMailBrandMigration
		}
		sealed, err := sealMailBody(current, mailEnvelopeVersion, mailAAD, body)
		if err != nil {
			return nil, false, errMailBrandMigration
		}
		return sealed, true, nil
	case mailEnvelopeVersion:
		body, err := openMailBody(current, mailEnvelopeVersion, mailAAD, raw)
		if err != nil {
			return nil, false, errMailBrandMigration
		}
		if _, err = decodeMailPayload(body); err != nil {
			return nil, false, errMailBrandMigration
		}
		return raw, false, nil
	default:
		return nil, false, errMailBrandMigration
	}
}
