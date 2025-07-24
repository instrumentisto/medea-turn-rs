#
# Dockerfile of `instrumentisto/medea-turn` Docker image.
#


#
# Stage `dist` creates project distribution.
#

# https://hub.docker.com/_/rust
ARG rust_ver=latest
FROM rust:${rust_ver} AS dist
ARG rustc_mode=release
ARG rustc_opts=--release

# Create user and group files, which will be used in a running container to run
# the process as an unprivileged user.
RUN mkdir -p /out/etc/ \
 && echo 'nobody:x:65534:65534:nobody:/:' > /out/etc/passwd \
 && echo 'nobody:x:65534:' > /out/etc/group

# Prepare Cargo workspace for building dependencies only.
COPY bin/Cargo.toml bin/Cargo.lock /app/bin/
COPY Cargo.toml /app/
WORKDIR /app/
RUN mkdir -p bin/src/ && touch bin/src/lib.rs \
 && mkdir -p src/ && touch src/lib.rs
WORKDIR /app/bin/

# Build dependencies only.
RUN cargo build -p medea-turn-bin --lib ${rustc_opts}
# Remove fingreprints of pre-built empty project sub-crates to rebuild them
# correctly later.
RUN rm -rf /app/bin/target/${rustc_mode}/.fingerprint/medea-turn*

# Prepare project sources for building.
COPY bin/ /app/bin/
COPY src/ /app/src/

# Build project distribution binary.
# TODO: use --out-dir once stabilized
# TODO: https://github.com/rust-lang/cargo/issues/6790
RUN cargo build -p medea-turn-bin ${rustc_opts}

# Prepare project distribution binary and all dependent dynamic libraries.
RUN cp /app/bin/target/${rustc_mode}/medea-turn-bin /out/medea-turn \
 && ldd /out/medea-turn \
        # These libs are not reported by ldd(1) on binary,
        # but are vital for DNS resolution.
        # See: https://forums.aws.amazon.com/thread.jspa?threadID=291609
        /lib/$(uname -m)-linux-gnu/libnss_dns.so.2 \
        /lib/$(uname -m)-linux-gnu/libnss_files.so.2 \
    | awk 'BEGIN{ORS=" "}$1~/^\//{print $1}$3~/^\//{print $3}' \
    | sed 's/,$/\n/' \
    | tr -d ':' \
    | tr ' ' "\n" \
    | xargs -I '{}' cp -fL --parents '{}' /out/ \
 && rm -rf /out/out




#
# Stage `runtime` creates final Docker image to use in runtime.
#

# https://hub.docker.com/_/scratch
FROM scratch AS runtime

COPY --from=dist /out/ /

USER nobody:nobody

ENTRYPOINT ["/medea-turn"]
