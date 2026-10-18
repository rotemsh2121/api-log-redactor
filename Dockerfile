# Small official Python image (Debian "slim": no compilers or extra tools).
FROM python:3.12-slim

# Print logs immediately, and do not try to write .pyc files (the filesystem is read-only in Kubernetes).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Dependencies first, in their own layer: rebuilding after a code change reuses this cached layer.
# Only runtime dependencies (no pytest).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The code (tests are left out by .dockerignore) and default rules.
# In Kubernetes, a ConfigMap is mounted over /etc/redactor to supply the real rules.
COPY *.py ./
COPY rules.yaml /etc/redactor/rules.yaml

# Do not run as root.
USER 10001

EXPOSE 8080
ENTRYPOINT ["python", "redactor.py"]
CMD ["--serve", "--addr", ":8080", "--rules", "/etc/redactor/rules.yaml"]
