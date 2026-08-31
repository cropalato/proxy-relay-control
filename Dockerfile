FROM golang:1.27-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/relay ./cmd/relay

# The relay holds tenant proxy credentials and a signing key. Nothing else
# belongs in the image alongside them.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/relay /relay
USER 65532:65532
EXPOSE 3128 9090
ENTRYPOINT ["/relay"]
CMD ["serve"]
