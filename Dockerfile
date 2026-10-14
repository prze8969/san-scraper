FROM python:3.13-slim

WORKDIR /app

# Copy project files
COPY src/ /app/src/
COPY salvage /app/salvage

# Ensure execute permission
RUN chmod +x /app/salvage

ENTRYPOINT ["/app/salvage"]
