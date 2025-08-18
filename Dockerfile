FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY main.go go.mod go.sum /app
RUN CGO_ENABLED=0 GOOS=linux go build -a -o app .

FROM scratch
COPY --from=builder /app/app /app
ENTRYPOINT ["/app"]