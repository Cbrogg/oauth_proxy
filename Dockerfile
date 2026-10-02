FROM golang:1.26.3-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /facade ./cmd/facade

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
COPY --from=build /facade /facade
EXPOSE 8080
USER nobody
ENTRYPOINT ["/facade"]
