FROM golang:1.22.4 as builder

# Build stage

WORKDIR /usr/src/app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the rest of the application code
COPY . .

# Build the application
RUN go build -o /app/app

# Final stage
FROM alpine

RUN apk add --no-cache libc6-compat

# Copy the built application from the builder stage
COPY --from=builder /app/app /app
COPY --from=builder /usr/src/app/assetlinks.json /assetlinks.json
COPY --from=builder /usr/src/app/web /web
EXPOSE 8080

# Set the entry point to run the application
ENTRYPOINT ["/app"]
