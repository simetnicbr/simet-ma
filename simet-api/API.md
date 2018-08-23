# SIMET MA API

## System-wide config file

  <sysconf dir>/simet/simet-ma.conf

  $<VARIABLE> below refers to a variable set on the above file.
  The file follows the VARIABLE="contents with spaces" syntax,
  "" is optional when the shell would accept it without quotes.


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

