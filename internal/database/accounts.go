package database

import "context"

func MigrateAccounts(ctx context.Context, s *Store) error {
	for _, m := range []struct{ name, ddl string }{
		{"006_account_namespaces", "CREATE TABLE IF NOT EXISTS " + s.Table("go_account_namespaces") + ` (name VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY) ENGINE=InnoDB`},
		{"007_mail_challenges", "CREATE TABLE IF NOT EXISTS " + s.Table("go_mail_challenges") + ` (digest BINARY(32) PRIMARY KEY,user_uid BIGINT NOT NULL,version BIGINT NOT NULL,purpose VARCHAR(8) CHARACTER SET ascii NOT NULL,target_email VARCHAR(255) NOT NULL,issued_at BIGINT NOT NULL,expires_at BIGINT NULL,UNIQUE challenge_user(user_uid,purpose),INDEX challenge_expiry(expires_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`},
		{"008_captchas", "CREATE TABLE IF NOT EXISTS " + s.Table("go_captchas") + ` (session_digest BINARY(32) PRIMARY KEY,answer_digest BINARY(32) NOT NULL,expires_at BIGINT NOT NULL,INDEX captcha_expiry(expires_at)) ENGINE=InnoDB`},
		{"009_browser_limits", "CREATE TABLE IF NOT EXISTS " + s.Table("go_browser_limits") + ` (digest BINARY(32) PRIMARY KEY,count BIGINT NOT NULL,expires_at BIGINT NOT NULL,INDEX limit_expiry(expires_at)) ENGINE=InnoDB`},
		{"011_web_flashes", "CREATE TABLE IF NOT EXISTS " + s.Table("go_web_flashes") + ` (session_digest BINARY(32) NOT NULL,form VARCHAR(8) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,message TEXT NOT NULL,expires_at BIGINT NOT NULL,PRIMARY KEY(session_digest,form),INDEX flash_expiry(expires_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`},
	} {
		if err := s.ApplyMigration(ctx, m.name, m.ddl); err != nil {
			return err
		}
	}
	_, err := s.DB.ExecContext(ctx, "INSERT IGNORE INTO "+s.Table("go_account_namespaces")+" (name) VALUES ('email'),('mail'),('player-name'),('registration')")
	return err
}
