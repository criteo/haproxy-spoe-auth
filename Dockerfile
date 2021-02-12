FROM golang:1.15

# Using root user creates permission issues on the host, particularly with go.sum being regenerated within the container.
RUN useradd -s /bin/bash -m -U dev
USER dev

RUN go get github.com/cespare/reflex

ENTRYPOINT ["/scripts/entrypoint.sh"]