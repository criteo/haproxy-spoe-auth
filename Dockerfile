FROM golang:1.12.7-stretch

RUN useradd -s /bin/bash -m -U dev
USER dev

RUN go get github.com/cespare/reflex
COPY resources/reflex.conf /
COPY resources/entrypoint.sh /
COPY resources/run.sh /

ENTRYPOINT ["/entrypoint.sh"]