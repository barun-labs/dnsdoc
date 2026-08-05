FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
ADD https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64 /usr/local/bin/ttyd
RUN chmod +x /usr/local/bin/ttyd
COPY --from=build /src/target/release/dnsdoc /usr/local/bin/dnsdoc
ENV TERM=xterm-256color
EXPOSE 7681
# ponytail: fixed demo domain; make it a form/env if demo needs per-visitor domains
CMD ["ttyd", "-W", "dnsdoc", "example.com"]
