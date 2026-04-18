FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY src/ src/
COPY tests/ tests/
RUN pip install --quiet pytest
ENV PYTHONPATH=/app/src
CMD ["python", "-m", "pytest", "tests/", "-v", "--tb=short"]
