FROM gcr.io/distroless/static-debian12:nonroot
COPY agent /usr/local/bin/ligolo-agent
ENTRYPOINT ["/usr/local/bin/ligolo-agent"]
