FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /out/proxy ./cmd/proxy \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /out/agent ./cmd/agent \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /out/relayctl ./cmd/relayctl

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates busybox-static \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/proxy /usr/local/bin/ligolo-proxy
COPY --from=build /out/agent /usr/local/bin/ligolo-agent
COPY --from=build /out/relayctl /usr/local/bin/relayctl
WORKDIR /work
