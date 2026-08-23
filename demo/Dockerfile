# The showcase in a container.
#
# For trying gatecrash on a machine without Go and Node. It is deliberately *not* how a box is
# deployed: a real box is one static binary on a Pi, and adding a container runtime to a machine
# whose whole appeal is having none would be a strange trade. See deploy/README.md.

FROM golang:1.24-alpine AS build
WORKDIR /src

RUN apk add --no-cache nodejs npm && npm install -g pnpm@11

# Dependencies first, so a source change does not re-resolve the whole workspace.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/protocol/package.json packages/protocol/
COPY packages/ui/package.json packages/ui/
COPY apps/scanner/package.json apps/scanner/
COPY apps/attendee/package.json apps/attendee/
COPY apps/dashboard/package.json apps/dashboard/
COPY docs/package.json docs/
COPY bench/package.json bench/
COPY demo/package.json demo/
RUN pnpm install --frozen-lockfile

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# The three web apps are embedded in the binary, so they have to be built first or the box ships
# with an empty asset filesystem — which fails at a gate rather than here.
RUN pnpm -r build && ./scripts/build.sh

FROM alpine:3.20
RUN adduser -D -H -s /sbin/nologin gatecrash

COPY --from=build /src/dist/gatecrash-linux-amd64 /usr/local/bin/gatecrash
COPY --from=build /src/dist/gatecrash-keys /usr/local/bin/gatecrash-keys
COPY --from=build /src/dist/gatecrash-demo /usr/local/bin/gatecrash-demo

RUN mkdir -p /var/lib/gatecrash && chown gatecrash /var/lib/gatecrash
USER gatecrash
VOLUME /var/lib/gatecrash

EXPOSE 8080 8443

# The demo command rather than `serve`, because a container with no manifest would come up and
# wait, which looks like a hang to somebody trying it for the first time.
CMD ["gatecrash-demo"]
