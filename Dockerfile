# Multi-stage build for the server and client binaries.
FROM golang:1.19-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server && \
    CGO_ENABLED=0 go build -o /out/client ./cmd/client

FROM alpine:3.18
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/server /usr/local/bin/redis-dns-server
COPY --from=build /out/client /usr/local/bin/redis-dns-client
ENTRYPOINT ["/usr/local/bin/redis-dns-server"]
