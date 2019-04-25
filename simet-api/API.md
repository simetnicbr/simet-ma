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
  at $AGENT_VERSION_FILE.


## TOKEN and LMAP AGENT-ID API

  The agent token, required to authorize with SIMET-2 services, will
  be retrieved and refreshed by {simet,simetbox}_register_ma.sh.

  *  The agent token will be stored in $AGENT_TOKEN_FILE
  *  The LMAP agent-id will be stored in $AGENT_ID_FILE

  The <>_register_ma.sh script can be called at any time, so all reads
  from the above files must be atomic *or* must flock($AGENT_TOKEN_LOCK)
  in shared mode (reading) or exclusive mode (writing).  This lock
  protects both $AGENT_TOKEN_FILE and $AGENT_ID_FILE.

  If either file is missing, measurements are *NOT* to be carried out.


## Locks (misc)
  $AGENT_LOCK  -  runner/scheduler lock.  Protects a measurement run.
     take the shared lock to block measurements, take the exclusive
     lock to measure.

## Hooks

  Some of the API scripts (in shell) have (shell) hooks, or can have its
  internal functions replaced (via functions named FUNCTION_override).

  Hooks are highly integrated with the script, you usually need to
  manipulate local variables, etc.  As such, please read the script to
  know what hooks are available.

### simet_register_ma.sh (in the future, maybe simetbox_register_ma.sh)

  <libdir>/simet/simet_register_ma-hooks.sh
  <sysconf dir>/simet/simet_register_ma-hooks.sh


## Geolocation

  The simet-ma geolocation API is:
  simet\_geolocation.sh
     returns in stdout the geolocation information, as an LMAP metric
       result
     returns in stderr relevant error or progress messages
     returns in exit status 0 (ok), non-zero (error)

  The time the geolocation was carried out is informed in seconds since
  1900-01-01T00:00:00Z (NTP epoch).  Assume a 64-bit integer type for
  y2038k safety.

  Latitude and longitude are in degrees, floating point.  Negative is
  South/West, positive is North/East.

  simet-ma's simet\_geolocation.sh requires root access to work, unless
  returning data from cache (--from-cache command line option), in which
  case it just requires read access to the geolocation cache file.

  The simet-ma packaging must arrange for simet\_geolocation.sh to be
  run as root periodically.

  There is a simet\_geolocation\_legado.sh that is used to feed the
  legacy SIMET API with gelocation data.  It will be phased out and
  removed when we disable the legacy API.  The legacy script uses
  simet\_geolocation.sh to do the real work.
