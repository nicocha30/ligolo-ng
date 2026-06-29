FROM gcr.io/distroless/static-debian12:nonroot
COPY relaymcp /usr/local/bin/relaymcp
ENTRYPOINT ["/usr/local/bin/relaymcp"]
