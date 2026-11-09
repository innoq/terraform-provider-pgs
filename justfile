tofu := `command -v tofu`
acc_env := "TF_ACC=1 TF_ACC_TERRAFORM_PATH=" + tofu + " TF_ACC_PROVIDER_HOST=registry.opentofu.org TF_ACC_PROVIDER_NAMESPACE=local"

default:
    @just --list

# Static SQLite helpers uploaded to SSH hosts; embedded into the provider (internal/helperbin/bin).
helpers:
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o internal/helperbin/bin/linux_amd64 ./cmd/pgs-sqlhelper
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '-s -w' -o internal/helperbin/bin/linux_arm64 ./cmd/pgs-sqlhelper

build: helpers
    go build -o terraform-provider-pgs .

# Unit + acceptance tests (needs tofu, no containers). Acceptance tests are skipped silently
# without TF_ACC, so this recipe always sets it.
test: helpers
    {{acc_env}} go test ./...

# Acceptance tests only, verbose
testacc:
    {{acc_env}} go test ./internal/provider/ -v -timeout 20m

# End-to-end tests: a real pgs container plus an SSH host with sqlite3 (docker or podman)
e2e: helpers
    cd test/e2e && {{acc_env}} go test -tags e2e -v -count=1 -timeout 30m .

# Build into ./bin for use with dev_overrides (see .tofurc.example)
install: helpers
    mkdir -p bin && go build -o bin/terraform-provider-pgs .

lint:
    go vet ./...
    go vet -tags e2e ./test/e2e/

docs:
    go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@v0.25.0 generate --provider-name pgs --rendered-provider-name pgs

# E2E against the pgs image versions listed in test/e2e/pgs-versions.txt (a minute per version).
# Logs go to test/e2e/.logs/<version>.log. Fails if any version fails.
e2e-all: helpers
    {{acc_env}} test/e2e/run-all.sh

# Validate the release config and build every release archive locally, unsigned, into ./dist.
release-check:
    goreleaser check
    goreleaser release --snapshot --clean --skip=sign
