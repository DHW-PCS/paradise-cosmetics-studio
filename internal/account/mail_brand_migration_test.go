package account

import (
	"bytes"
	"crypto/cipher"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/testsupport"
)

const mailBrandTestKey = "synthetic-account-key-32-bytes-minimum"

func mailBrandTestBody(token string) []byte {
	return []byte(`{"uid":7,"version":9,"purpose":"verify","email":"person@example.invalid","token":"` + token + `","locale":"en","future":{"preserve":true},"unknown_number":12.5}`)
}

func mailBrandTestPayload(token string) mailPayload {
	return mailPayload{UID: 7, Version: 9, Purpose: "verify", Email: "person@example.invalid", Token: token, Locale: "en"}
}

func mailBrandTestCiphers(t *testing.T) (legacy, current cipher.AEAD) {
	t.Helper()
	legacy, err := mailCipherForLabel([]byte(mailBrandTestKey), legacyMailBrandAAD)
	if err != nil {
		t.Fatal(err)
	}
	current, err = mailCipher([]byte(mailBrandTestKey))
	if err != nil {
		t.Fatal(err)
	}
	return legacy, current
}

func sealMailBrandTestEnvelope(t *testing.T, aead cipher.AEAD, version int, label string, body []byte) json.RawMessage {
	t.Helper()
	raw, err := sealMailBody(aead, version, label, body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestMigrateMailBrandPayloadRewritesLegacyExactly(t *testing.T) {
	legacy, current := mailBrandTestCiphers(t)
	body := mailBrandTestBody("legacy-token")
	raw := sealMailBrandTestEnvelope(t, legacy, 1, legacyMailBrandAAD, body)

	converted, changed, err := migrateMailBrandPayload(legacy, current, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("legacy payload was not rewritten")
	}
	if bytes.Equal(converted, raw) {
		t.Fatal("legacy payload bytes were not resealed")
	}
	var envelope sealedMail
	if err = json.Unmarshal(converted, &envelope); err != nil || envelope.Version != mailEnvelopeVersion {
		t.Fatalf("converted envelope version=%d err=%v", envelope.Version, err)
	}
	opened, err := openMailBody(current, mailEnvelopeVersion, mailAAD, converted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, body) {
		t.Fatal("conversion did not preserve exact decrypted JSON bytes")
	}
	got, err := decodeMailPayload(opened)
	if err != nil {
		t.Fatal(err)
	}
	if want := mailBrandTestPayload("legacy-token"); got != want {
		t.Fatalf("decoded payload=%+v want=%+v", got, want)
	}
}

func TestMigrateMailBrandPayloadLeavesCurrentEnvelopeByteIdentical(t *testing.T) {
	legacy, current := mailBrandTestCiphers(t)
	body := mailBrandTestBody("current-token")
	raw := sealMailBrandTestEnvelope(t, current, mailEnvelopeVersion, mailAAD, body)

	unchanged, changed, err := migrateMailBrandPayload(legacy, current, raw)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("current payload was marked for rewrite")
	}
	if !bytes.Equal(unchanged, raw) {
		t.Fatal("current payload bytes changed")
	}
	opened, err := openMailBody(current, mailEnvelopeVersion, mailAAD, unchanged)
	if err != nil || !bytes.Equal(opened, body) {
		t.Fatal("current payload did not remain readable", err)
	}
}

func TestMailRuntimeRejectsLegacyEnvelopeAndAcceptsMigratedEnvelope(t *testing.T) {
	legacy, current := mailBrandTestCiphers(t)
	body := mailBrandTestBody("runtime-token")
	raw := sealMailBrandTestEnvelope(t, legacy, 1, legacyMailBrandAAD, body)
	mail := &Mail{cipher: current}

	if _, err := mail.open(raw); err == nil {
		t.Fatal("runtime accepted a v1 account-mail envelope")
	}
	converted, changed, err := migrateMailBrandPayload(legacy, current, raw)
	if err != nil || !changed {
		t.Fatalf("legacy conversion failed: changed=%v err=%v", changed, err)
	}
	got, err := mail.open(converted)
	if err != nil {
		t.Fatal("runtime rejected the migrated envelope", err)
	}
	if want := mailBrandTestPayload("runtime-token"); got != want {
		t.Fatalf("runtime payload=%+v want=%+v", got, want)
	}
}

func TestMigrateMailBrandPayloadRejectsInvalidInput(t *testing.T) {
	legacy, current := mailBrandTestCiphers(t)
	validBody := mailBrandTestBody("valid-token")
	validV2 := sealMailBrandTestEnvelope(t, current, mailEnvelopeVersion, mailAAD, validBody)
	tamperedV2 := func() json.RawMessage {
		var envelope sealedMail
		if err := json.Unmarshal(validV2, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Sealed[0] == 'A' {
			envelope.Sealed = "B" + envelope.Sealed[1:]
		} else {
			envelope.Sealed = "A" + envelope.Sealed[1:]
		}
		raw, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}()
	badBody := []byte(`{"uid":0,"version":9,"purpose":"other","email":"person@example.invalid","token":"","locale":"en"}`)
	unknownVersion := json.RawMessage(`{"v":3,"sealed":"AAAA"}`)
	malformedEnvelope := json.RawMessage(`{"v":1`)
	malformedSealed := json.RawMessage(`{"v":1,"sealed":"%%%"}`)
	wrongVersionLabel := sealMailBrandTestEnvelope(t, current, 2, legacyMailBrandAAD, validBody)

	otherLegacy, err := mailCipherForLabel([]byte("another-account-key-32-bytes-minimum"), legacyMailBrandAAD)
	if err != nil {
		t.Fatal(err)
	}
	wrongKeyV1 := sealMailBrandTestEnvelope(t, otherLegacy, 1, legacyMailBrandAAD, validBody)

	for name, raw := range map[string]json.RawMessage{
		"unknown version":          unknownVersion,
		"malformed envelope":       malformedEnvelope,
		"malformed sealed":         malformedSealed,
		"tampered v2":              tamperedV2,
		"v1 bad payload":           sealMailBrandTestEnvelope(t, legacy, 1, legacyMailBrandAAD, badBody),
		"v2 bad payload":           sealMailBrandTestEnvelope(t, current, mailEnvelopeVersion, mailAAD, badBody),
		"v2 under legacy label":    wrongVersionLabel,
		"v1 sealed with wrong key": wrongKeyV1,
		"v2 encrypted as v1":       sealMailBrandTestEnvelope(t, current, 1, legacyMailBrandAAD, validBody),
	} {
		t.Run(name, func(t *testing.T) {
			out, changed, err := migrateMailBrandPayload(legacy, current, raw)
			if !errors.Is(err, errMailBrandMigration) {
				t.Fatalf("error=%v, want opaque migration failure", err)
			}
			if changed || out != nil {
				t.Fatalf("invalid payload changed=%v output=%q", changed, out)
			}
			if strings.Contains(err.Error(), string(validBody)) || strings.Contains(err.Error(), "person@example.invalid") {
				t.Fatal("migration error leaked payload detail")
			}
		})
	}
}

type mailBrandMetadata struct {
	ID          int64
	Operation   string
	Topic       string
	AvailableAt int64
	LeaseUntil  int64
	ClaimedBy   sql.NullString
	Attempts    int64
	CompletedAt sql.NullInt64
	BlockedAt   sql.NullInt64
	ErrorClass  sql.NullString
}

type mailBrandRow struct {
	Metadata mailBrandMetadata
	Payload  []byte
}

func insertMailBrandRow(t *testing.T, store *database.Store, metadata mailBrandMetadata, payload []byte) int64 {
	t.Helper()
	result, err := store.DB.Exec("INSERT INTO "+store.Table("go_outbox")+" (operation_key,topic,payload,available_at,lease_until,claimed_by,attempts,completed_at,blocked_at,error_class) VALUES (?,?,?,?,?,?,?,?,?,?)",
		metadata.Operation, metadata.Topic, payload, metadata.AvailableAt, metadata.LeaseUntil, metadata.ClaimedBy, metadata.Attempts, metadata.CompletedAt, metadata.BlockedAt, metadata.ErrorClass)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func readMailBrandRow(t *testing.T, store *database.Store, id int64) mailBrandRow {
	t.Helper()
	var row mailBrandRow
	err := store.DB.QueryRow("SELECT id,operation_key,topic,payload,available_at,lease_until,claimed_by,attempts,completed_at,blocked_at,error_class FROM "+store.Table("go_outbox")+" WHERE id=?", id).
		Scan(&row.Metadata.ID, &row.Metadata.Operation, &row.Metadata.Topic, &row.Payload, &row.Metadata.AvailableAt, &row.Metadata.LeaseUntil, &row.Metadata.ClaimedBy, &row.Metadata.Attempts, &row.Metadata.CompletedAt, &row.Metadata.BlockedAt, &row.Metadata.ErrorClass)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestMigrateMailBrandDatabaseRewritesAllRowsAndMetadata(t *testing.T) {
	store, _ := testsupport.Database(t, "mail-brand-")
	legacy, current := mailBrandTestCiphers(t)

	rows := []struct {
		metadata mailBrandMetadata
		token    string
		version  int
	}{
		{mailBrandMetadata{Operation: "mail:legacy-active", Topic: MailTopic, AvailableAt: 11, LeaseUntil: 12, ClaimedBy: sql.NullString{String: "worker-active", Valid: true}, Attempts: 3}, "active-token", 1},
		{mailBrandMetadata{Operation: "mail:legacy-completed", Topic: MailTopic, AvailableAt: 21, Attempts: 2, CompletedAt: sql.NullInt64{Int64: 101, Valid: true}}, "completed-token", 1},
		{mailBrandMetadata{Operation: "mail:legacy-blocked", Topic: MailTopic, AvailableAt: 31, Attempts: 5, BlockedAt: sql.NullInt64{Int64: 202, Valid: true}, ErrorClass: sql.NullString{String: "mail_payload", Valid: true}}, "blocked-token", 1},
		{mailBrandMetadata{Operation: "mail:current", Topic: MailTopic, AvailableAt: 41, Attempts: 1, CompletedAt: sql.NullInt64{Int64: 303, Valid: true}}, "current-token", 2},
		{mailBrandMetadata{Operation: "collect:other-topic", Topic: "texture.collect", AvailableAt: 51, Attempts: 7, CompletedAt: sql.NullInt64{Int64: 404, Valid: true}}, "not-account-mail", 0},
	}
	before := make([]mailBrandRow, len(rows))
	for i, row := range rows {
		var payload []byte
		switch row.version {
		case 1:
			payload = sealMailBrandTestEnvelope(t, legacy, 1, legacyMailBrandAAD, mailBrandTestBody(row.token))
		case 2:
			payload = sealMailBrandTestEnvelope(t, current, mailEnvelopeVersion, mailAAD, mailBrandTestBody(row.token))
		default:
			payload = []byte(`{"topic":"texture.collect","keep":true}`)
		}
		row.metadata.ID = insertMailBrandRow(t, store, row.metadata, payload)
		before[i] = readMailBrandRow(t, store, row.metadata.ID)
	}

	if err := MigrateMailBrand(t.Context(), store, []byte(mailBrandTestKey)); err != nil {
		t.Fatal(err)
	}
	after := make([]mailBrandRow, len(before))
	for i, original := range before {
		after[i] = readMailBrandRow(t, store, original.Metadata.ID)
		if after[i].Metadata != original.Metadata {
			t.Fatalf("row %d metadata changed: before=%+v after=%+v", original.Metadata.ID, original.Metadata, after[i].Metadata)
		}
		if original.Metadata.Topic != MailTopic {
			if !bytes.Equal(after[i].Payload, original.Payload) {
				t.Fatalf("non-mail row %d payload changed", original.Metadata.ID)
			}
			continue
		}
		oldBody, err := openMailBody(legacy, 1, legacyMailBrandAAD, original.Payload)
		if err != nil {
			oldBody, err = openMailBody(current, mailEnvelopeVersion, mailAAD, original.Payload)
		}
		if err != nil {
			t.Fatalf("row %d source payload unreadable: %v", original.Metadata.ID, err)
		}
		newBody, err := openMailBody(current, mailEnvelopeVersion, mailAAD, after[i].Payload)
		if err != nil {
			t.Fatalf("row %d migrated payload unreadable: %v", original.Metadata.ID, err)
		}
		if !bytes.Equal(newBody, oldBody) {
			t.Fatalf("row %d body bytes changed", original.Metadata.ID)
		}
		if rows[i].version == 2 && !bytes.Equal(after[i].Payload, original.Payload) {
			t.Fatalf("row %d current payload was rewritten", original.Metadata.ID)
		}
		if rows[i].version == 1 && bytes.Equal(after[i].Payload, original.Payload) {
			t.Fatalf("row %d legacy payload was not rewritten", original.Metadata.ID)
		}
	}

	if err := MigrateMailBrand(t.Context(), store, []byte(mailBrandTestKey)); err != nil {
		t.Fatal(err)
	}
	for _, first := range after {
		second := readMailBrandRow(t, store, first.Metadata.ID)
		if second.Metadata != first.Metadata || !bytes.Equal(second.Payload, first.Payload) {
			t.Fatalf("rerun changed row %d", first.Metadata.ID)
		}
	}
}

func TestMigrateMailBrandDatabaseRollsBackEntireTransaction(t *testing.T) {
	store, _ := testsupport.Database(t, "mail-brand-rollback-")
	legacy, _ := mailBrandTestCiphers(t)

	validID := insertMailBrandRow(t, store, mailBrandMetadata{Operation: "mail:rollback-valid", Topic: MailTopic, AvailableAt: 1}, sealMailBrandTestEnvelope(t, legacy, 1, legacyMailBrandAAD, mailBrandTestBody("do-not-leak")))
	badID := insertMailBrandRow(t, store, mailBrandMetadata{Operation: "mail:rollback-bad", Topic: MailTopic, AvailableAt: 2}, []byte(`{"v":1,"sealed":"not-a-valid-envelope"}`))
	validBefore := readMailBrandRow(t, store, validID)
	badBefore := readMailBrandRow(t, store, badID)

	err := MigrateMailBrand(t.Context(), store, []byte(mailBrandTestKey))
	if !errors.Is(err, errMailBrandMigration) {
		t.Fatalf("error=%v, want opaque migration failure", err)
	}
	if strings.Contains(err.Error(), "do-not-leak") || strings.Contains(err.Error(), "person@example.invalid") {
		t.Fatal("migration error leaked plaintext")
	}
	if got := readMailBrandRow(t, store, validID); !bytes.Equal(got.Payload, validBefore.Payload) || got.Metadata != validBefore.Metadata {
		t.Fatal("valid row was not rolled back")
	}
	if got := readMailBrandRow(t, store, badID); !bytes.Equal(got.Payload, badBefore.Payload) || got.Metadata != badBefore.Metadata {
		t.Fatal("invalid row changed during rollback")
	}
}
