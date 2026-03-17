FROM golang:1.26-alpine AS build
WORKDIR /src
# Download GeoIP database during build
RUN apk add --no-cache curl
COPY . .
RUN make assets || true
RUN go build -o /dmarcer ./cmd/dmarcer

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /dmarcer /usr/local/bin/dmarcer
VOLUME /data
ENV DMARCER_DB_PATH=/data/dmarcer.db
EXPOSE 8080
ENTRYPOINT ["dmarcer"]
