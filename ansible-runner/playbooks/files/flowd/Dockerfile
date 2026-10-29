# flowd - Sentry Lens's flow collector (IPFIX, NetFlow v9, sFlow -> ClickHouse).
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /flowd .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /flowd /flowd
USER 65532:65532
EXPOSE 2055/udp 4739/udp 6343/udp 8080/tcp
ENTRYPOINT ["/flowd"]
CMD ["run", "--config", "/etc/flowd/flowd.json"]
