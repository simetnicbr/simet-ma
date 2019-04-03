# SIMET MA API

## System-wide config

  <libdir>/simet/simet-ma.conf
  <sysconfdir>/simet/simet-ma.conf

  $<VARIABLE> below refers to a variable set on the above files.  The
  file follows the VARIABLE="contents with spaces" syntax, "" is
  optional when the shell would accept it without quotes.

  First, the one in libdir is read.  Then, the one in sysconfdir is read
  (*if* it exists, it is not required to be there).  The last definition
  for each variable "wins".

  The config files are not to be modifiable by the same user that runs
  the SIMET suite (unless it is running as root, which is also not
  advised).


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

  Beware of file system permission issues if you call these scripts as
  different users (e.g. "root" and "nicbr-simet").


## LMAP scheduler API

  Simet-lmapd is responsible for scheduling and running periodic and
  bootup non-critical tasks.  A task is critical if it must be able to
  run even when simet-lmapd is non-functional, or if it must be able to
  run regardless of the Measurement Agent being registered.

  The LMAP engine will only carry hardcoded administrative tasks, until
  successfully configured by receiving a valid schedule from the LMAP
  controller.  This requires that the Measurement Agent be registered,
  as the controller requires a valid token before it will issue any
  schedules.

  JSON-rendered lmap-control config with the hardcoded LMAP capabilities
  go into <libdir>/lmap/registry.d/\*.json.  Each module that adds a
  capability must add a JSON file in there that defines the capability.

  Tasks that requires executable programs not present in one of the
  capabilities will be refused.

  There are a few "general" capabilities and/or programs that MUST be
  available, these are documented by the hardcoded capabilities of
  simet-ma.

  JSON-rendered lmap-control config with the hardcoded task definitions
  go into <libdir>/lmap/config.d/\*.json.  Each module that implements a
  predefined task must define the lmap-control::tasks::task object(s)
  required using a file in this directory.  Other predefined
  configuration also goes into this directory, such as hardcoded
  schedules and predefined events and schedules.

  Tasks present in the schedule that are not defined anywhere will cause
  the schedule to be refused entirely.  Care must be taken for this to
  never happen to the hardcoded configuration.

  JSON-rendered per-agent lmap-control configs with the agent-id,
  group-id go in /etc/simet/lmap/\*.json:

  <sysconfdir>/simet/lmap/agent-id.json - agent id set when the
       measurement agent is registered (LMAP "preboot").
  <sysconfdir>/simet/lmap/group-id.json - group id, set when the
       measurement agent is registered (LMAP "preboot").

  The per-agent section of the schedule is volatile, and MUST be reset
  at every agent boot.  The agent will reset the volatile portion of the
  schedule to a default schedule.  It will also attempt to retrieve new
  schedules at every boot, as well as periodically.

  <runstatedir>/lmap/lmap-schedule.json - variable schedule
       received from the controller

  Tasks present in the schedule that are not defined anywhere will cause
  the schedule to be refused entirely.  Care must be taken for this to
  never happen to the default schedule (i.e. it must be fully compatible
  with the hardcoded configuration).

  All hardcoded schedules, tasks, events, as well as other such
  identifiers must be prefixed by "ma-local\_", except when it is
  explicitly specified otherwise in the documentation.

  For fleet resilience reasons, the MA must be able to register itself
  as well as periodically refresh its schedule even when misconfigured
  by the controller.  simet-ma implements this by running such tasks as
  boot services as well as from the system cron daemon at a low
  frequency with high spread, so they will eventually run even if lmapd
  is not running.

  For safety, security and resilience reasons, software/firmware auto
  update tasks must be completely independent of the lmap core.


## Locks (misc)
  $AGENT\_LOCK  -  runner/scheduler lock.  Protects a measurement run.
     take the shared lock to block measurements, take the exclusive
     lock to measure.

  $AGENT\_TOKEN\_LOCK   -  general config lock.  Protects agent-id,
     agent token, LMAP config, and so on.  Take the exclusive lock
     when doing a non-atomic update.

  Locks are empty files, locked using flock.  Beware permission issues
  with the lock directory and lock files when scripts are run with
  different privilege levels (e.g. root and a non-privileged user).


## Hooks

  Some of the API scripts (in shell) have (shell) hooks, or can have its
  internal functions replaced (via functions named FUNCTION\_override).

  Hooks are highly integrated with the script, you usually need to
  manipulate local variables, etc.  As such, please read the script to
  know what hooks are available.

### simet\_register\_ma.sh (in the future, maybe simetbox\_register\_ma.sh)

  <libdir>/simet/simet\_register\_ma-hooks.sh
  <sysconfdir>/simet/simet\_register\_ma-hooks.sh


## Geolocation

  Right now, only the openwrt (SIMETBox) version of simet-ma has any
  geolocation capabilities, and the related functionality is not hosted
  or implemented in simet-ma.

  The geolocation API is:
  simet\_geolocation.sh
     returns in stdout the geolocation information
     returns in stderr relevant error or progress messages
     returns in exit status 0 (ok), non-zero (error)

  stdout format:
     <unix time of measurement, seconds>
     <latitude> <longitude> <precision in meters>

     Unix time is a large positive integer:
       * Number of seconds since 1970-01-01 00:00:00 UTC
       * y2038-safe: assume a 64-bit integer type
     Latitude and longitude are in degrees, floating point.
       * As defined by ISO C for printf of floats (double)
       * Negative is South/West, positive is North/East.

  Caching, query limits, and sideband REST API access to persist agent
  geolocation and other such sidechannels are not specified, but they do
  exist.

