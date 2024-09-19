FROM debian:stable-slim AS base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install build-essential libssl-dev -y && apt clean

WORKDIR /app
COPY *.c .

FROM base AS build

RUN gcc server.c -o server -lssl -lcrypto -pthread

FROM base AS run

WORKDIR /app
COPY --from=build /app/server ./server
CMD ./server