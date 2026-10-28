# The collector as a container (collector.yml, docker mode): the same binary
# Sentry Lens hands out, in a distroless image (CA certificates, no shell).
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/sentry-collector .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sentry-collector /sentry-collector
ENTRYPOINT ["/sentry-collector", "run"]
