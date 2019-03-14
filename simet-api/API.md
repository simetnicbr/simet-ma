# SIMET MA API

## System-wide config file

  <libdir>/simet/simet-ma.conf
  <sysconf dir>/simet/simet-ma.conf

  $<VARIABLE> below refers to a variable set on the above files.
  The file follows the VARIABLE="contents with spaces" syntax,
  "" is optional when the shell would accept it without quotes.

  First, the one in libdir is read.  Then, the one in sysconf dir
  is read (*if* it exists, it is not required to be there).  The
  last definition for each variable "wins".


## API version

  The full agent version (e.g. simet-ma/<version>) is available
  at $AGENT\_VERSION\_FILE.


## TOKEN and LMAP AGENT-ID API

  The agent token, required to authorize with SIMET-2 services, will
  be retrieved and refreshed by {simet,simetbox}\_register\_ma.sh.

  *  The agent token will be stored in $AGENT\_TOKEN\_FILE
  *  The LMAP agent-id will be stored in $AGENT\_ID\_FILE

  The <>\_register\_ma.sh script can be called at any time, so all reads
  from the above files must be atomic *or* must flock($AGENT\_TOKEN\_LOCK)
  in shared mode (reading) or exclusive mode (writing).  This lock
  protects both $AGENT\_TOKEN\_FILE and $AGENT\_ID\_FILE.

  If either file is missing, measurements are *NOT* to be carried out.


## Locks (misc)
  $AGENT\_LOCK  -  runner/scheduler lock.  Protects a measurement run.
     take the shared lock to block measurements, take the exclusive
     lock to measure.

## Hooks

  Some of the API scripts (in shell) have (shell) hooks, or can have its
  internal functions replaced (via functions named FUNCTION\_override).

  Hooks are highly integrated with the script, you usually need to
  manipulate local variables, etc.  As such, please read the script to
  know what hooks are available.

### simet\_register\_ma.sh (in the future, maybe simetbox\_register\_ma.sh)

  <libdir>/simet/simet\_register\_ma-hooks.sh
  <sysconf dir>/simet/simet\_register\_ma-hooks.sh


## Geolocation

  Right now, only the openwrt (SIMETBox) version has any geolocation
  capabilities, and the related functionality is not hosted or
  implemented in simet-ma.

  The geolocation API is:
  simet\_geolocation.sh
     returns in stdout the geolocation information
     returns in stderr relevant error or progress messages
     returns in exit status 0 (ok), non-zero (error)

  stdout format:
     <unix time of measurement, seconds>
     <latitude> <longitude> <precision in meters>

     Latitude and longitude are in degrees, floating point.
     Negative is South/West, positive is North/East.

  Caching, query limits, and sideband REST API access to persist agent
  geolocation and other such sidechannels are not specified, but they do
  exist.

