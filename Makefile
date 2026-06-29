export GO111MODULE=on

VERSION=$(shell date +"%Y.%m.%d")

BUILD=$(shell git rev-parse HEAD)
BASEDIR=./dist

LDFLAGS=-ldflags "-s -w -X main.build=${BUILD} -buildid=${BUILD}"
GCFLAGS=-gcflags=all=-trimpath=$(shell echo ${HOME})
ASMFLAGS=-asmflags=all=-trimpath=$(shell echo ${HOME})

GOFILES=`go list -buildvcs=false ./...`
GOFILESNOTEST=`go list -buildvcs=false ./... | grep -v test`

# Make Directory to store executables
$(shell mkdir -p ${BASEDIR})

# goreleaser build --config .goreleaser.yml --rm-dist --skip-validate
all: linux windows
	@chmod +x dist/*

mac: lint
	@env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${BASEDIR}/ligolo-ng-relay-proxy-darwin_amd64 cmd/proxy/main.go
	@env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${BASEDIR}/ligolo-ng-relay-agent-darwin_amd64 cmd/agent/main.go

linux: lint
	@env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${BASEDIR}/ligolo-ng-relay-proxy-linux_amd64 cmd/proxy/main.go
	@env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${BASEDIR}/ligolo-ng-relay-agent-linux_amd64 cmd/agent/main.go

windows: lint
	@env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${BASEDIR}/ligolo-ng-relay-proxy-windows_amd64.exe cmd/proxy/main.go
	@env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${BASEDIR}/ligolo-ng-relay-agent-windows_amd64.exe cmd/agent/main.go

tidy:
	@go mod tidy

update: tidy
	@go get -v -d ./...
	@go get -u all

dep: ## Get the dependencies
	@go install github.com/goreleaser/goreleaser
	@go install github.com/securego/gosec/v2/cmd/gosec@latest

lint: ## Lint the files
	@env CGO_ENABLED=0 go fmt ${GOFILES}
	@env CGO_ENABLED=0 go vet ${GOFILESNOTEST}

security:
	@go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	@go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet -include=G123 -tests ./...

relay-test:
	@./test/relay/run.sh

release:
	@goreleaser release --config .goreleaser.yaml

clean:
	@rm -rf ${BASEDIR}

terminal_proxy:
	go run cmd/proxy/main.go -selfcert

terminal_agent:
	go run cmd/agent/main.go -connect localhost:11601 -ignore-cert

terminal_relayctl:
	go run cmd/relayctl/main.go chains

terminal_relaymcp:
	go run cmd/relaymcp/main.go -http 127.0.0.1:9090


.PHONY: all linux windows tidy update dep lint security relay-test release clean terminal terminal_relayctl terminal_relaymcp
