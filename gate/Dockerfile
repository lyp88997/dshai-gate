FROM golang:1.23-alpine AS build
WORKDIR /src
COPY main.go login.html ./
RUN go mod init dshai-gate && CGO_ENABLED=0 go build -ldflags "-s -w" -o /dsh-gate .

FROM alpine:3.20
COPY --from=build /dsh-gate /usr/local/bin/dsh-gate
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/dsh-gate"]
