# Test-environment provisioning only. Project source is mounted read-only at runtime.
FROM node:22-bookworm-slim AS typescript
RUN npm install --global --ignore-scripts typescript@5.9.3

FROM python:3.12-slim-bookworm
COPY --from=typescript /usr/local/bin/node /usr/local/bin/node
COPY --from=typescript /usr/local/lib/node_modules/typescript /opt/typescript
COPY --from=typescript /usr/lib/x86_64-linux-gnu/libstdc++.so.6* /usr/lib/x86_64-linux-gnu/
COPY --from=typescript /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/
RUN python -m pip install --no-cache-dir mcp==1.30.0 pydantic==2.14.2 jsonschema==4.26.0 click==8.5.0 setuptools==80.9.0 wheel==0.45.1 build==1.3.0
WORKDIR /repo
