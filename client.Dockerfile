FROM debian:stable-slim AS base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install build-essential libssl-dev -y && apt clean

WORKDIR /app

FROM base AS build

COPY *.c .
COPY *.h .
RUN gcc client.c -o client -lssl -lcrypto -pthread

FROM base AS run

WORKDIR /app
COPY --from=build /app/client ./client
CMD ./client