# Research-only sanitizer image candidate. Not independently admitted as a sandbox.
# Exact official Ubuntu manifest digest pulled on Butcher on 2026-10-20.
FROM ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libclang-rt-dev g++ python3 \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*
RUN mkdir -p /work /input /seeds /output
WORKDIR /work
ENTRYPOINT ["python3"]
