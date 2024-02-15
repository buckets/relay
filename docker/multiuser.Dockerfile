# -- Stage 1 -- #
FROM nimlang/nim:1.6.18-alpine@sha256:e54f241d4cc4c7e677641a535df6f5cae2e6fa527cb36f53a4c7bd77214b1b80 as builder
WORKDIR /app
RUN apk update && apk add libsodium-static libsodium musl-dev
RUN nimble refresh
RUN nimble install -y nimble
COPY bucketsrelay.nimble .
RUN nimble install -y --depsOnly --verbose
COPY . .
COPY docker/config.nims .
RUN nimble c -o:brelay -d:release src/brelay

# -- Stage 2 -- #
FROM alpine:3.13.12@sha256:16fd981ddc557fd3b38209d15e7ee8e3e6d9d4d579655e8e47243e2c8525b503
WORKDIR /root/
RUN apk update && apk add libressl3.1-libcrypto sqlite-dev
COPY --from=builder /app/brelay /usr/local/bin/
RUN mkdir -p /data
CMD ["/usr/local/bin/brelay", "--database", "/data/bucketsrelay.sqlite", "server", "--address", "0.0.0.0", "--port", "8080"]
