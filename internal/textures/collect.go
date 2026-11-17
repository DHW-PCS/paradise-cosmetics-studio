package textures

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"paradise-cosmetics-studio/internal/outbox"
)

// CollectTopic is the outbox topic for unreferenced original-file removal.
const CollectTopic = "texture.collect"

type CollectPayload struct {
	Hash       string `json:"hash"`
	Generation int64  `json:"generation"`
}

// EnqueueCollect records the physical collection intent in the business
// transaction. The generation is read under the shared hash lock.
func (s *Service) EnqueueCollect(ctx context.Context, tx *sql.Tx, operationKey, hash string) error {
	generation, err := s.lockHash(ctx, tx, hash)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(CollectPayload{Hash: hash, Generation: generation})
	if err != nil {
		return err
	}
	queue := &outbox.Store{Database: s.Store, Now: s.Now}
	return queue.Enqueue(ctx, tx, operationKey, CollectTopic, payload)
}

// Handler rechecks current references before unlinking the published original.
// The business delete already happened; this handler only performs the file
// side effect and is safe to retry.
func (s *Service) Handler() outbox.Handler {
	return func(ctx context.Context, task outbox.Task) error {
		var payload CollectPayload
		if err := json.Unmarshal(task.Payload, &payload); err != nil || payload.Hash == "" {
			return &outbox.DeliveryFailure{Class: "texture_payload"}
		}
		removed := false
		err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
			var err error
			removed, err = s.Collect(ctx, tx, payload.Hash, payload.Generation)
			return err
		})
		if err != nil {
			if errors.Is(err, ErrPath) {
				return &outbox.DeliveryFailure{Class: "texture_path"}
			}
			if errors.Is(err, ErrFile) {
				return &outbox.DeliveryFailure{Class: "texture_collect", Delay: time.Minute}
			}
			return err
		}
		_ = removed
		return nil
	}
}
