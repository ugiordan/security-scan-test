# Intentional Hadolint issues for testing
FROM python:latest

# DL3008: Pin versions in apt-get install
RUN apt-get update && apt-get install -y \
    curl \
    vim \
    && rm -rf /var/lib/apt/lists/*

# DL3013: Pin versions in pip install
RUN pip install flask requests

# DL3025: Use JSON array format for CMD
CMD python app.py

# DL3059: Multiple RUN commands (inefficient)
RUN echo "test1"
RUN echo "test2"
RUN echo "test3"

# DL4006: Use SHELL or avoid pipefail
RUN curl -sL https://example.com | bash

# DL3020: Use COPY instead of ADD for files
ADD config.json /app/

# Running as root (security issue)
USER root
