FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN GOMAXPROCS=1 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/agent-manager ./cmd/agent-manager

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/agent-manager /agent-manager
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/agent-manager"]
