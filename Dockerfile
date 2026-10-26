# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
# empty: the VERSION file (embedded in the binary) is used
ARG VERSION=
# /data must be writable by whatever UID the container runs as (compose runs it as you,
# so it can read your home); a new named volume copies this mode. Files inside are 0600.
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w ${VERSION:+-X main.version=${VERSION}}" -o /out/depgate . \
 && mkdir -p /out/data /out/projects \
 && chmod 1777 /out/data

# distroless/static: CA certificates, tzdata, no shell, runs as uid 65532
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/depgate /usr/local/bin/depgate
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/projects /projects
ENV DEPGATE_CONTAINER=1 \
    DEPGATE_DATA=/data \
    DEPGATE_ROOTS=/projects
VOLUME ["/data"]
EXPOSE 7777
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["/usr/local/bin/depgate", "--health"]
ENTRYPOINT ["/usr/local/bin/depgate"]
