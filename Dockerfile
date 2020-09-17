# syntax = docker/dockerfile:experimental
FROM docker.io/library/golang:1.14.1 as builder
LABEL maintainer="maintainer@cilium.io"
ADD . /go/src/github.com/cilium/clustermesh-apiserver
WORKDIR /go/src/github.com/cilium/clustermesh-apiserver
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux go build

FROM docker.io/library/alpine:3.9.3 as certs
RUN apk --update add ca-certificates

# FROM scratch
FROM docker.io/library/golang:1.14.1
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/clustermesh-apiserver/etcd-config.yaml /var/lib/cilium/etcd-config.yaml
COPY --from=builder /go/src/github.com/cilium/clustermesh-apiserver/clustermesh-apiserver /usr/bin/clustermesh-apiserver
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
WORKDIR /
CMD ["/usr/bin/clustermesh-apiserver"]
