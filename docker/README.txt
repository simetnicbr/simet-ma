SIMET-MA Docker instructions/examples
=====================================

The top-level Makefile.am may have "docker*" targets that are examples of
how to use simet-ma with docker.

docker/Dockerfile:
    A simple example of how to *build* from source

docker/Dockerfile.reference-container:
    The SIMET-MA container for a SIMET-MA measurement node hosted
    in a docker container.  It auto-updates itself, and uses reference
    production packages from NIC.br instead of building new ones.


To build simet-ma:
docker build -t simet-ma:local -f docker/Dockerfile .
docker build -t simet-ma:nicbr -f docker/Dockerfile.reference-container .

* Note that you must give the container some sort of network access for it
  to work (it downloads the build environment, and in the "reference
  container" case, the official binaries for simet-ma and simet-lmapd) so
  you might need to add "--network host" or other network access
  configuration to the docker line.

* Note that for the container to be able to geolocate, it requires
  CAP_NET_ADMIN.  It should also have CAP_NET_RAW as some future SIMET2 tests
  will require it.

This will create a simet-ma:local (or simet-ma:nicbr) image with simet-ma
installed inside.  Some environment variables may be set to create images with
an specific purpose, please refer to the Dockerfiles for details.

NOTE: the "reference container" version *auto-upgrades* the simet-ma components
inside it.  It also exits every so often, so that it can try to at least apply
security updates to itself (it does so at container start/restart).

It is best to arrange for a "docker pull" when the reference container exits,
though, as that will update everything.


NIC.br distributes the reference container image (for docker pull) at:
https://docker-download.simet.nic.br/medidor-simet/simet-ma:latest


To run the full simet-ma agent, with identity (agent-id, group-id, vlabel)
persistence:
docker run --init -dt --restart=unless-stopped \
           --network host --cap-add NET_ADMIN --cap-add NET_RAW \
           --mount source=simet-ma-id,target=/opt/simet/etc/simet \
	   simet-ma:local

To run an specific test (TWAMP, TCPBW, GEOLOC):
docker run -t --rm \
           --network host --cap-add NET_ADMIN --cap-add NET_RAW \
           --mount source=simet-ma-id,target=/opt/simet/etc/simet \
           -e SIMET_RUN_TEST=TWAMP simet-ma:local

(replace TWAMP above with TCPBW or GEOLOC as desired)

To see what it is doing:
docker container logs <simet-ma:local container>
docker exec -it <simet-ma:local container> cat /var/log/syslog

To trigger an immediate measurement run:
docker exec -u nicbr-simet:nicbr-simet -it <simet-ma:local container> \
            /opt/simet/bin/simet-ma_run.sh <options>


CALIBRATION SETUP (internal)
============================

Using simet-runner/test/services-example.json, prepare a services.json
file that points to the local measurement peer behind the calibration rig.

Add this file to the persistent volume (simet-ma-id), along with a
simet-ma.conf file with the contents:

SIMET_SERVICELIST_OVERRIDE=/opt/simet/etc/simet/services.json

Note that we're mounting simet-ma-id at /opt/simet/etc/simet in the
examples above, so that means one should add a services.json and
simet-ma.conf to the root of that volume.


VIRTUAL LABEL SETUP (internal)
==============================

It is possible to force a virtual label for testing purposes when
initially creating a simet-ma container.  This is generally unsafe, do not
use this facility: it is provided for internal use.

To set a specific virtual label:

1. Export SIMET2_VLABEL=TST0<somerandomstuff> to the environment.

2. Add the required "-e SIMET2_VLABEL" parameter to docker run.  It is
   only effective for the very first run of that container when identity
   persistence is being done.  Alternatively, create the container with
   that environment variable already, but beware running more than one
   container with the same SIMET2_VLABEL at the same time, as that can
   result in misbehavior and access loss to measurement data.


DISABLED VIRTUAL LABEL SETUP:

To disable SIMET portal attachment to ephemeral MAs being used for testing
purposes:

1. *CREATE* the container image with environment SIMET2_VLABEL=DISABLED,
   so that it will use that virtual label when it first contacts the
   SIMET2 system.

2. The MA will declare to the SIMET2 servers that it is not available
   for pairing when the virtual label is either disabled or missing.

It will be generally impossible to interact with the MA through the portal
should its virtual label be set to DISABLED.  This *will* result in
important functionality loss, such as access to that MA measurement
results and reports.
