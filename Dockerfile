FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o authguardian ./cmd

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/authguardian .
COPY --from=builder /app/migrations ./migrations
COPY --from=builder /app/.env ./.env

EXPOSE 8080
CMD ["./authguardian"]