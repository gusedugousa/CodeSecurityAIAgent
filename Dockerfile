FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        build-essential \
        libicu-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY app ./app
COPY configs ./configs

RUN pip install --upgrade pip

# Security scanners are optional at runtime (ToolRunner marks them unavailable if missing).
# Installed before the app package so the app's pinned OpenTelemetry versions win the
# resolution last (checkov/semgrep pull their own, older, incompatible otel packages).
RUN pip install semgrep bandit pip-audit checkov

RUN pip install -e ".[dev]"

# Go-distributed binary scanners. trufflehog/trivy have official curl|sh installers;
# gitleaks ships only a versioned tarball and osv-scanner only a raw per-arch binary,
# so those two are resolved via the GitHub releases API instead. set -e ensures any
# single tool's failure fails the whole build rather than silently skipping it.
RUN set -e \
    && ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin \
    && GITLEAKS_VERSION=$(curl -sSf https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep -m1 '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && curl -sSfL -o /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${ARCH}.tar.gz" \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    && OSV_VERSION=$(curl -sSf https://api.github.com/repos/google/osv-scanner/releases/latest | grep -m1 '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && curl -sSfL -o /usr/local/bin/osv-scanner \
        "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${ARCH}" \
    && chmod +x /usr/local/bin/osv-scanner \
    && POUTINE_VERSION=$(curl -sSf https://api.github.com/repos/boostsecurityio/poutine/releases/latest | grep -m1 '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && POUTINE_ARCH=$(uname -m | sed 's/x86_64/x86_64/;s/aarch64/arm64/') \
    && curl -sSfL -o /tmp/poutine.tar.gz \
        "https://github.com/boostsecurityio/poutine/releases/download/v${POUTINE_VERSION}/poutine_Linux_${POUTINE_ARCH}.tar.gz" \
    && tar -xzf /tmp/poutine.tar.gz -C /usr/local/bin poutine \
    && rm /tmp/poutine.tar.gz

# .NET SDK for Meziantou.Analyzer (Roslyn analyzer, invoked via `dotnet build`).
# python:3.11-slim has no .NET runtime; installed via Microsoft's official
# dotnet-install.sh script rather than apt, to control the exact SDK channel.
# Meziantou.Analyzer itself is NOT installed here - it's a per-analysis NuGet
# PackageReference restored at runtime into a scratch copy of the scanned repo
# (see app/tools/meziantou.py), same category of runtime network dependency as
# pip-audit/osv-scanner's vulnerability database lookups.
RUN curl -sSfL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --channel 9.0 --install-dir /usr/share/dotnet \
    && rm /tmp/dotnet-install.sh \
    && ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet
ENV DOTNET_NOLOGO=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1

COPY . .

RUN mkdir -p /app/data/workspaces /app/data/reports

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
