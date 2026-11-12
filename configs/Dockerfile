FROM golang:1.27.4-alpine AS build
RUN apk add --no-cache git build-base linux-headers && mkdir -p /out
# Reviewed upstream release commits; never build a moving branch.
RUN git init /src/xray && cd /src/xray && git remote add origin https://github.com/XTLS/Xray-core && git fetch --depth=1 origin 676eaf66f8f05d4d558ee7a74b4736623d3feeb9 && git checkout --detach FETCH_HEAD
RUN cd /src/xray && CGO_ENABLED=0 GOTOOLCHAIN=local go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/xray ./main
RUN git init /src/dns && cd /src/dns && git remote add origin https://github.com/DNSCrypt/dnscrypt-proxy && git fetch --depth=1 origin c33302bc279e4d298fa19b99be8b35778db9a901 && git checkout --detach FETCH_HEAD
RUN cd /src/dns && CGO_ENABLED=0 GOTOOLCHAIN=local go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/dnscrypt-proxy ./dnscrypt-proxy
RUN git init /src/awg && cd /src/awg && git remote add origin https://github.com/amnezia-vpn/amneziawg-go && git fetch --depth=1 origin b5928efb6ca19f0153958460c3d141f04abc5c2e && git checkout --detach FETCH_HEAD
RUN cd /src/awg && CGO_ENABLED=0 GOTOOLCHAIN=local go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/amneziawg-go .
RUN git init /src/tools && cd /src/tools && git remote add origin https://github.com/amnezia-vpn/amneziawg-tools && git fetch --depth=1 origin ee0f0a9aa34ff0a0da4b3433b9512781cfe02843 && git checkout --detach FETCH_HEAD && make -C src && cp src/wg /out/awg

FROM alpine:3.23
RUN apk add --no-cache ca-certificates iproute2 iptables bind-tools tini
COPY --from=build /out/ /usr/local/bin/
COPY configs/awg-entrypoint.sh /usr/local/bin/awg-entrypoint
RUN chmod 755 /usr/local/bin/awg-entrypoint
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["xray", "run", "-c", "/etc/xray/config.json"]
