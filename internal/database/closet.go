package database

import "context"

// MigrateCloset installs the additive reward-source table for Go-created
// closet entries.
func MigrateCloset(ctx context.Context, s *Store) error {
	for _, m := range []struct{ name, ddl string }{
		{"014_closet_rewards", "CREATE TABLE IF NOT EXISTS " + s.Table("go_closet_rewards") + ` (user_uid BIGINT NOT NULL,texture_tid BIGINT NOT NULL,uploader_uid BIGINT NOT NULL,amount BIGINT NOT NULL,active BOOLEAN NOT NULL,UNIQUE pair(user_uid,texture_tid),INDEX active_rewards(active)) ENGINE=InnoDB`},
	} {
		if err := s.ApplyMigration(ctx, m.name, m.ddl); err != nil {
			return err
		}
	}
	return nil
}
