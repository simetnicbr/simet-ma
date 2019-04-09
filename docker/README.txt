SIMET-MA Docker instructions/examples
=====================================

The toplevel Makefile.am may have "docker*" targets that are examples of how to
use simet-ma with docker.


To build simet-ma:
docker build -t simet-ma:local -f docker/Dockerfile .

This will create a simet-ma:local image with simet-ma installed inside.  Some
environment variables may be set to create images with an specific purpose,
please refer to the Dockerfile for details.

Note that you must give the container some sort of network access for it to work
(it downloads the build environment) so you might need to add --network host or
other network access configurantion to the docker line.


To run the full simet-ma agent, with agent-id persistence:
docker run --init -dt --rm --network host --mount source=simet-ma-id,target=/opt/simet/etc/simet simet-ma:local

To run an specific test (TWAMP, TCPBW, GEOLOC)
docker run -t --rm --network host --mount source=simet-ma-id,target=/opt/simet/etc/simet \
                -e SIMET_RUN_TEST=TWAMP simet-ma:local

To see what it is doing:
docker container logs <simet-ma:local container>
docker exec -it <simet-ma:local container> cat /var/log/syslog

To trigger an immediate measurement run:
docker exec -u nicbr-simet:nicbr-simet -it <simet-ma:local container> /opt/simet/bin/simet-ma_periodic.sh <options>



CALIBRATION SETUP
=================

Using simet-runner/test/services-example.json, prepare a services.json file
that points to the local measurement peer behind the calibration rig.

Add this file to the persistent volume (simet-ma-id), along with a
simet-ma.conf file with the contents:

SIMET_SERVICELIST_OVERRIDE=/opt/simet/etc/simet/services.json

Note that we're mounting simet-ma-id at /opt/simet/etc/simet in the examples
above, so that means one should add a services.json and simet-ma.conf to the
root of that volume.
