# fleet-git runtime image (W363 §1). Build context: a directory holding the
# static musl binary as `fleet-git`, built on the host:
#
#   (cd oss/yubaba && cargo build --release --target x86_64-unknown-linux-musl -p fleet-git)
#   docker buildx build --platform linux/amd64 -f oss/yubaba/crates/fleet-git/Dockerfile \
#       --output type=oci,dest=<dir>,tar=false <ctx-with-fleet-git>
#
# The binary is cross-built on the host rather than in a builder stage: the
# camp's musl toolchain is native-speed, a builder stage under emulation is not.
# Alpine is one host the startup probe accepts, not the only one: fleet-git
# finds http-backend via `git --exec-path` and runs on glibc distros' git too.
# git (GPLv2) is exec'd as a separate program; if this image is ever given to a
# third party, ship Alpine's git aport source with it (W363 §1 "Licence").
FROM alpine:3.22
RUN apk add --no-cache git git-daemon \
 && /usr/bin/git --version
COPY fleet-git /usr/local/bin/fleet-git
RUN /usr/local/bin/fleet-git probe
ENTRYPOINT ["/usr/local/bin/fleet-git", "serve"]
