FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795
RUN apk add --no-cache python-3.10 py3.10-pip && rm -rf /var/cache/apk/*
WORKDIR /app
COPY pyproject.toml ./
COPY src/ src/
COPY tests/ tests/
RUN pip install --quiet --break-system-packages pytest
ENV PYTHONPATH=/app/src
USER nonroot
CMD ["python3.10", "-m", "pytest", "tests/", "-v", "--tb=short"]
