# -- Stage 1 -- #
FROM nimlang/nim:1.6.10-alpine@sha256:408ebac99ad2d170a59e7a09c10e82e7336cf71fa38c7a1322aaa598a54d32c2 as builder
WORKDIR /app
RUN apk update && apk add libsodium-static libsodium musl-dev
RUN nimble refresh
COPY bucketsrelay.nimble .
RUN nimble install -y --depsOnly --verbose
COPY . .
COPY docker/config.nims .
RUN nim c -o:brelay -d:relaysingleusermode -d:release src/brelay

# -- Stage 2 -- #
FROM alpine:3.13.12@sha256:16fd981ddc557fd3b38209d15e7ee8e3e6d9d4d579655e8e47243e2c8525b503
WORKDIR /root/
RUN apk update && apk add libressl3.1-libcrypto sqlite-dev
COPY --from=builder /app/brelay /usr/local/bin/
CMD ["/usr/local/bin/brelay", "server", "--address", "0.0.0.0", "--port", "8080"]
