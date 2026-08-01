FROM mcr.microsoft.com/playwright/python:v1.61.0-noble

ARG TARGETARCH
COPY shadowpath-dist/ /tmp/wheels/

RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) wheel_arch="x86_64" ;; \
      arm64) wheel_arch="aarch64" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 2 ;; \
    esac; \
    wheel="$(find /tmp/wheels -type f -name "*-${wheel_arch}.whl" -print -quit)"; \
    test -n "${wheel}"; \
    python -m pip install --no-cache-dir "${wheel}" "playwright==1.61.0"; \
    rm -rf /tmp/wheels

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["velvet"]
CMD ["shadowpath", "demo", "--execute", "--output-dir", "/reports/shadowpath"]
