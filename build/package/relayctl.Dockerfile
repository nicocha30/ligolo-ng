FROM gcr.io/distroless/static-debian12:nonroot
COPY relayctl /usr/local/bin/relayctl
ENTRYPOINT ["/usr/local/bin/relayctl"]
