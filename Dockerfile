FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/agent-manager ./cmd/agent-manager

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/agent-manager /agent-manager
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/agent-manager"]
