FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY main.go go.mod go.sum /app
RUN CGO_ENABLED=0 GOOS=linux go build -a -o app .

FROM scratch
COPY --from=builder /app/app /app
ENTRYPOINT ["/app"]