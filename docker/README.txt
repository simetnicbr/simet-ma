SIMET-MA Docker instructions/examples
=====================================

The toplevel Makefile.am may have "docker*" targets that are examples of
how to use simet-ma with docker.


To build simet-ma:
docker build -t simet-ma:local -f docker/Dockerfile .

This will create a simet-ma:local image with simet-ma installed inside.
Some environment variables may be set to create images with an specific
purpose, please refer to the Dockerfile for details.

Note that you must give the container some sort of network access for it
to work (it downloads the build environment) so you might need to add
--network host or other network access configurantion to the docker line.


To run the full simet-ma agent, with identity (agent-id, group-id, vlabel)
persistence:
docker run --init -dt --rm --network host \
           --mount source=simet-ma-id,target=/opt/simet/etc/simet \
	   simet-ma:local

To run an specific test (TWAMP, TCPBW, GEOLOC):
docker run -t --rm --network host \
           --mount source=simet-ma-id,target=/opt/simet/etc/simet \
           -e SIMET_RUN_TEST=TWAMP simet-ma:local

(replace TWAMP above with TCPBW or GEOLOC as desired)

To see what it is doing:
docker container logs <simet-ma:local container>
docker exec -it <simet-ma:local container> cat /var/log/syslog

To trigger an immediate measurement run:
docker exec -u nicbr-simet:nicbr-simet -it <simet-ma:local container> \
            /opt/simet/bin/simet-ma_periodic.sh <options>


CALIBRATION SETUP
=================

Using simet-runner/test/services-example.json, prepare a services.json
file that points to the local measurement peer behind the calibration rig.

Add this file to the persistent volume (simet-ma-id), along with a
simet-ma.conf file with the contents:

SIMET_SERVICELIST_OVERRIDE=/opt/simet/etc/simet/services.json

Note that we're mounting simet-ma-id at /opt/simet/etc/simet in the
examples above, so that means one should add a services.json and
simet-ma.conf to the root of that volume.


VIRTUAL LABEL SETUP
===================

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

It will be generally impossible to interact with the MA through the portal
should its virtual label be set to DISABLED.  This *will* result in
important functionality loss, such as access to that MA measurement
results and reports.
