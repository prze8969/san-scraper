FROM python:3.13-slim

WORKDIR /app

# Copy project files and tests
COPY src/ /app/src/
COPY tests/ /app/tests/
COPY Genesis_Track3_PS2_Sample_Files-main/ /app/Genesis_Track3_PS2_Sample_Files-main/
COPY salvage /app/salvage

# Ensure unix line endings and execute permission
RUN sed -i 's/\r$//' /app/salvage && chmod +x /app/salvage

ENTRYPOINT ["/app/salvage"]
