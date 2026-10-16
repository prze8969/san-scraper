FROM python:3.11-slim

WORKDIR /app

# Copy all source code, decoders, tools, and offline verification fixtures
COPY src/ /app/src/
COPY tools/ /app/tools/
COPY tests/ /app/tests/
COPY Makefile /app/Makefile
COPY salvage /app/salvage

# Ensure unix line endings and execute permissions
RUN sed -i 's/\r$//' /app/salvage && chmod +x /app/salvage

ENTRYPOINT ["/app/salvage"]
