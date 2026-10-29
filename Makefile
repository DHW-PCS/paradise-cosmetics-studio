export GOTOOLCHAIN := go1.27.3

.PHONY: frontend build check
frontend:
	go run ./cmd/assetgen
	cd web/frontend && corepack yarn install --frozen-lockfile --ignore-scripts --non-interactive
	cd web/frontend && corepack yarn build

build: frontend
	mkdir -p dist
	go build -trimpath -o dist/blessing-skin ./cmd/blessing-skin

check:
	go test ./internal/admission ./internal/config ./internal/processlock ./internal/database ./internal/identity ./internal/oauthserver ./internal/httpapp ./internal/site ./cmd/blessing-skin ./internal/maintenance ./internal/outbox
