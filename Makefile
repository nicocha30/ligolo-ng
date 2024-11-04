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
	@env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${BASEDIR}/ligolo-ng-proxy-darwin_amd64 cmd/proxy/main.go
	@env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${BASEDIR}/ligolo-ng-agent-darwin_amd64 cmd/agent/main.go

linux: lint
	@env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${BASEDIR}/ligolo-ng-proxy-linux_amd64 cmd/proxy/main.go
	@env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${BASEDIR}/ligolo-ng-agent-linux_amd64 cmd/agent/main.go

windows: lint
	@env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${BASEDIR}/ligolo-ng-proxy-windows_amd64.exe cmd/proxy/main.go
	@env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${BASEDIR}/ligolo-ng-agent-windows_amd64.exe cmd/agent/main.go

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
	@gosec -tests ./...

release:
	@goreleaser release --config .github/goreleaser.yml

clean:
	@rm -rf ${BASEDIR}

terminal_proxy:
	go run cmd/proxy/main.go -selfcert

terminal_agent:
	go run cmd/agent/main.go -connect localhost:11601 -ignore-cert


.PHONY: all linux windows tidy update dep lint security release clean terminal
