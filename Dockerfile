FROM ubuntu:20.04

MAINTAINER Ketan Nilangekar <ketan@threatwatch.io>

USER root

SHELL [ "/bin/bash", "-c" ]

COPY build_docker.sh /tmp
COPY motd /tmp
#COPY entrypoint.sh /tmp
RUN /bin/bash /tmp/build_docker.sh
ENTRYPOINT /bin/bash
