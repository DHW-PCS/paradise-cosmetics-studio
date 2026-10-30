export GOTOOLCHAIN := go1.27.3

.PHONY: frontend build check
frontend:
	go run ./cmd/assetgen
	cd web/frontend && corepack yarn install --frozen-lockfile --ignore-scripts --non-interactive
	cd web/frontend && corepack yarn build

build: frontend
	mkdir -p dist/licenses
	go build -trimpath -o dist/blessing-skin ./cmd/blessing-skin
	cp internal/pcre/LICENCE dist/licenses/PCRE2.txt
	cp THIRD_PARTY_NOTICES.md dist/THIRD_PARTY_NOTICES.md

check:
	go test ./internal/legacy/password ./internal/pcre ./internal/legacy/rules ./internal/account ./internal/players ./internal/searchstring ./internal/textures ./internal/captcha ./internal/admission ./internal/config ./internal/processlock ./internal/database ./internal/identity ./internal/oauthserver ./internal/httpapp ./internal/site ./cmd/blessing-skin ./internal/maintenance ./internal/outbox
