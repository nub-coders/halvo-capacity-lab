ARG REFERENCE_IMAGE
FROM ${REFERENCE_IMAGE}
# The accepted reference image is retained, not rebuilt or retagged. Only this
# capacity fixture differs; runtimes and shared reference layers are reused.
COPY capacity_fixtures.py /app/capacity_fixtures.py
COPY server.py /app/server.py
