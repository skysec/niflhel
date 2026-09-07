# Build infrastructure only. Applications and frameworks go in app images.
# Release builders must override these with approved digest-pinned references.
ARG GUEST_OS_IMAGE=alpine:3.21
FROM ${GUEST_OS_IMAGE}
RUN apk add --no-cache ca-certificates iproute2 iptables runc \
    && mkdir -p /state /bootstrap /app-image /run/niflhel
# Build with make guest; use the repository root as build context.
COPY bin/niflhel-agent /usr/sbin/niflhel-agent
COPY bin/niflhel-agent /sbin/niflhel-init
ENTRYPOINT ["/sbin/niflhel-init"]
