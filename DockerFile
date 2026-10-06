FROM python:3.11-slim

WORKDIR /app

COPY engine.py .

ENV PORT=8765
EXPOSE 8765

CMD ["python", "engine.py", "server"]
