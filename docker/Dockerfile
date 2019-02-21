# Creates a builder image and a run image for SIMET-MA
# Copyright (c) 2019 NIC.br <medicoes@simet.nic.br>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.  In every case, additional
# restrictions and permissions apply, refer to the COPYING file in the
# program Source for details.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License and the COPYING file in the program Source
# for details.


##
##  Builder image
##

## Docker build arguments
##    distro:    (debian:stretch), debian:jessie, ubuntu:bionic, ubuntu:xenial
##    BUILD_DIR: /usr/src/simet/simet-ma/

# Base distro
ARG DISTRO=debian:stretch
FROM $DISTRO

LABEL description="SIMET2 Measurement Agent builder environment"
LABEL maintainer="Henrique de Moraes Holschuh <henrique@nic.br>"

# general build depends
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get -y dist-upgrade && \
    apt-get -y install --install-recommends \
      build-essential autoconf automake libtool fakeroot debhelper

# package-specific build-depends
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install --install-recommends \
      libjson-c-dev cmake libcurl4-gnutls-dev pkg-config \
      lsb-release

RUN echo "umask 022" > /etc/profile.d/safe-umask && \
    adduser --disabled-password --uid 100000 --gecos "Docker Builder,,," --home "/usr/src/simet" --shell /bin/bash builder

ARG BUILD_DIR=/usr/src/simet/simet-ma/
COPY --chown=builder:builder ./ "$BUILD_DIR"

USER builder:builder
WORKDIR $BUILD_DIR

#CMD ./autogen.sh && ./configure --prefix=/opt/simet-ma && make install
#but if we did that, we'd need to figure out the lib packages we need...
RUN dpkg-buildpackage --build=binary -uc -us -rfakeroot && mkdir /tmp/debs && mv ../*deb /tmp/debs/

##
##  Runtime image
##
##  Warning: assumes the deb creates the nicbr-simet user, and installs to /opt/simet/
##

FROM $DISTRO
LABEL description="SIMET2 Measurement Agent"
LABEL maintainer="Henrique de Moraes Holschuh <henrique@nic.br>"

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get -y dist-upgrade
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install sudo

COPY --from=0 /tmp/debs/ /tmp/debs/
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install /tmp/debs/*deb ; DEBIAN_FRONTEND=noninteractive apt-get -y -f install
RUN rm -fr /tmp/debs /usr/sbin/policy-rc.d
COPY docker/*.sh /opt/simet/bin/

# We want to make sure these will not be reused unless persisted,
# i.e. it must not be present in the image... but the deb package
# might have created them when it was installed.
RUN rm -f /opt/simet/etc/simet/agent-id /opt/simet/etc/simet/agent.jwt
VOLUME /opt/simet/etc/simet

##
## Start service upon container run.
##

# Meaningful environment variables one might want to hardcode in the image
# for specific needs.  Please refer to simet-ma.foreground.sh for details
ENV SIMET_INETUP_DISABLE=
ENV SIMET_CRON_DISABLE=
ENV SIMET_REFRESH_AGENTID=
ENV SIMET_RUN_TEST=

ENTRYPOINT [ "/opt/simet/bin/simet-ma.foreground.sh" ]
