FROM gcr.io/distroless/static-debian12:nonroot
COPY proxy /usr/local/bin/ligolo-proxy
ENTRYPOINT ["/usr/local/bin/ligolo-proxy"]
