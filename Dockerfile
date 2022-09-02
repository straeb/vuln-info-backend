# syntax=docker/dockerfile:1
FROM golang:1.18-alpine

WORKDIR /app
COPY go.mod ./
COPY go.sum ./
COPY cron-config.yml /cron-config.yml
COPY .env /.env
RUN go mod download
COPY . ./
RUN go build -o /vuln-info-backend
CMD [ "/vuln-info-backend" ]