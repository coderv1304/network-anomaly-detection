FROM golang:1.22-alpine AS go-builder
WORKDIR /app/capture
COPY capture/go.mod .
COPY capture/go.sum .
RUN apk add --no-cache libpcap-dev gcc musl-dev
RUN go mod download
COPY capture/*.go .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o /go-bin/capture

FROM python:3.11-slim AS python-builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt
COPY . .

FROM alpine:3.18 AS runtime
# Install runtime dependencies
RUN apk add --no-cache ca-certificates libpcap && update-ca-certificates
# Copy Go binary
COPY --from=go-builder /go-bin/capture /usr/local/bin/capture
# Copy Python environment
COPY --from=python-builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=python-builder /app /app
WORKDIR /app
ENV PYTHONUNBUFFERED=1
EXPOSE 5000 8080
# Start both services via supervisord (install supervisor)
RUN apk add --no-cache supervisor
COPY supervisord.conf /etc/supervisord.conf
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
