# ==========================================
# Stage 1: Build static Go binary (Zero CGO)
# ==========================================
FROM golang:alpine AS builder

WORKDIR /src

# Allow Go to automatically fetch the toolchain version specified in go.mod if needed
ENV GOTOOLCHAIN=auto
ENV CGO_ENABLED=0

# Cache dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy source and compile stripped static binary
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN go build -trimpath -ldflags="-s -w" -o /out/cvebot ./cmd/cvebot

# ==========================================
# Stage 2: Minimal Alpine Runtime (~15MB)
# ==========================================
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -S cvebot && adduser -S -G cvebot cvebot && \
    mkdir -p /data && chown -R cvebot:cvebot /data

WORKDIR /app
COPY --from=builder /out/cvebot /app/cvebot

# Persist SQLite DB in /data volume by default
ENV DB_PATH=/data/cve_tracker.db

USER cvebot
VOLUME ["/data"]

ENTRYPOINT ["/app/cvebot"]
