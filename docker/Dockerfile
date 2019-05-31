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
##    BUILD_DIR: /usr/src/simet
##    SIMET_LMAPD: https://github.com/simetnicbr/simet-lmapd/archive/master.tar.gz
##    DEB_BUILD_OPTIONS: "noautodbgsym nodoc terse hardening=+all"

# Base distro
ARG DISTRO=debian:stretch
FROM $DISTRO

LABEL description="SIMET2 Measurement Agent builder environment"
LABEL maintainer="Henrique de Moraes Holschuh <henrique@nic.br>"

# general build depends
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get -y dist-upgrade && \
    apt-get -y install --install-recommends \
      build-essential autoconf automake libtool fakeroot debhelper \
      cmake pkg-config

# package-specific build-depends (simet-ma)
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install --install-recommends \
      libjson-c-dev libcurl4-gnutls-dev lsb-release

# package-specific build-depends (simet-lmapd)
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install --install-recommends \
      libjson-c-dev libxml2-dev libevent-dev check

# distro-specific build-depends (e.g. due to hardening=+all em DEB_BUILD_OPTIONS)
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install --install-recommends \
      hardening-wrapper || true

RUN echo "umask 022" > /etc/profile.d/safe-umask && \
    adduser --disabled-password --uid 100000 --gecos "Docker Builder,,," --home "/usr/src/simet" --shell /bin/bash builder

ARG SIMET_LMAPD=https://github.com/simetnicbr/simet-lmapd/archive/master.tar.gz
ARG BUILD_DIR=/usr/src/simet
ADD --chown=builder:builder "$SIMET_LMAPD" "$BUILD_DIR"/simet-lmapd.tar.gz
COPY --chown=builder:builder ./ "$BUILD_DIR"/simet-ma

USER builder:builder
WORKDIR $BUILD_DIR

# unpack and build every subdirectory, using the debian packaging support.
# we could avoid doing a package buikd, something like:
#    CMD ./autogen.sh && ./configure --prefix=/opt/simet-ma \
#        && make install
# but if we did that, we'd need to figure out the lib packages we need,
# whether it uses autoconf or cmake, etc.

ARG DEB_BUILD_OPTIONS="noautodbgsym nodoc terse hardening=+all"

RUN tar zxf simet-lmapd.tar.gz && rm -f simet-lmapd.tar.gz
RUN find . -maxdepth 1 -type d '!' -name ".*" | while read -r i ; do echo $i ; \
	( cd "$i" && dpkg-buildpackage -b -uc -us -rfakeroot ) ; \
    done
RUN mkdir /tmp/debs && mv *deb /tmp/debs/

##
##  Runtime image
##
##  Warning: assumes the deb creates the nicbr-simet user, and installs to /opt/simet/
##

FROM $DISTRO
LABEL description="SIMET2 Measurement Agent"
LABEL maintainer="Henrique de Moraes Holschuh <henrique@nic.br>"

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade ; \
    DEBIAN_FRONTEND=noninteractive apt-get -y install sudo procps rsyslog logrotate

# We need to run this snippet under a policy-rc.d that refuses service
# starts, we don't want the simet-ma initscript/unit to run!
#
# Also, Debian jessie apt-get knows not how to install from files, one must
# use the dpkg -i <packages> ; apt-get -f install ; dpkg -i <packages> sequence.
COPY --from=0 /tmp/debs/ /tmp/debs/
RUN if DEBIAN_FRONTEND=noninteractive apt-get -y install /tmp/debs/*deb ; then \
        DEBIAN_FRONTEND=noninteractive apt-get -y -f install ; \
    else \
        DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/debs/*deb ; \
        DEBIAN_FRONTEND=noninteractive apt-get -y -f install ; \
        DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/debs/*deb ; \
    fi

RUN rm -fr /tmp/debs /usr/sbin/policy-rc.d
COPY docker/*.sh /opt/simet/bin/

# We want to make sure these will not be reused unless persisted,
# i.e. it must not be present in the image... but the deb package
# might have created them when it was installed.
RUN rm -f /opt/simet/etc/simet/agent-id /opt/simet/etc/simet/agent.jwt /opt/simet/etc/simet/lmap/agent-id.json /opt/simet/etc/simet/lmap/group-id.json
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
