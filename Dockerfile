FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/Gahrcoder/depshield"
LABEL org.opencontainers.image.description="Supply chain security scanner for npm packages"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY . .
RUN pip install --no-cache-dir -e .

ENTRYPOINT ["depshield"]
CMD ["scan", "/scan"]
