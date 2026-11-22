FROM ubuntu:24.04

MAINTAINER Ketan Nilangekar <ketan@threatwatch.io>

USER root

SHELL [ "/bin/bash", "-c" ]

COPY build_docker.sh /tmp
COPY motd /tmp
# Optional: pip requirement spec for twigs (defaults to the latest twigs on PyPI)
ARG TWIGS_PIP_SPEC=twigs
#COPY entrypoint.sh /tmp
RUN /bin/bash /tmp/build_docker.sh
ENTRYPOINT ["/usr/local/bin/twigs"]
