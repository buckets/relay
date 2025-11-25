# -- Stage 1 -- #
FROM nimlang/nim:2.2.6-alpine-regular as builder
WORKDIR /app
RUN apk update && apk add libsodium-static libsodium musl-dev
RUN nimble refresh
RUN nimble install -y https://github.com/iffy/pkger/
COPY pkger.json .
COPY ./pkger ./pkger
RUN pkger fetch
COPY ./ ./
COPY docker/config.nims .
RUN find .
RUN nim c -d:release -o:brelay src/bucketsrelay/v2/server2.nim
RUN strip brelay

# -- Stage 2 -- #
FROM alpine:3.22.2
WORKDIR /root/
RUN apk update && apk add libressl4.1-libcrypto sqlite-dev
COPY --from=builder /app/brelay /usr/local/bin/
RUN mkdir -p /data
EXPOSE 8080
CMD ["/usr/local/bin/brelay", "--database", "/data/bucketsrelay.sqlite", "server", "--address", "0.0.0.0", "--port", "8080"]
