FROM debian:stable-slim AS base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y \
    build-essential \
    cmake \
    libssl-dev \
    && apt clean

WORKDIR /app

FROM base AS build

COPY src ./src
COPY CMakeLists.txt ./
RUN cmake -B build -S . && \
    cmake --build build --target client

FROM base AS run

WORKDIR /app
COPY --from=build /app/build/client ./client

ENTRYPOINT ["./client"]
