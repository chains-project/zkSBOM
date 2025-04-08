FROM rust:latest

WORKDIR /usr/src/zksbom

# Copy the Cargo.toml and Cargo.lock files first
COPY Cargo.toml Cargo.lock ./

# Copy the source code
COPY src ./src
COPY config ./config

COPY sboms ./sboms

# Copy the static files
COPY static ./static

# Copy the Rocket.toml configuration file
COPY Rocket.toml Rocket.toml

# Build the application
RUN cargo build --release

# Expose the HTTP port
EXPOSE 8000

# Set the command to run the compiled binary
CMD ["./target/release/zksbom"]
