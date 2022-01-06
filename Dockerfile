FROM golang:1.17

# Using root user creates permission issues on the host, particularly with go.sum being regenerated within the container.
RUN useradd -s /bin/bash -m -U dev

RUN go install github.com/go-delve/delve/cmd/dlv@v1.8.0
RUN go install github.com/cespare/reflex@v0.3.1

WORKDIR /usr/app
ADD go.mod go.mod
ADD go.sum go.sum
RUN go mod download
RUN chown -R dev /usr/app

USER dev

ENTRYPOINT ["/scripts/entrypoint.sh"]