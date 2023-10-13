# SIMET MA API

This documents the internal API of simet-ma, although it does go
into some details of the SIMET2 web API.

## System-wide config

  <libdir>/simet/simet-ma.conf
  <libdir>/simet/conf.d/*.conf
  <sysconfdir>/simet/simet-ma.conf

  $<VARIABLE> below refers to a variable set on the above files.  The
  file follows the VARIABLE="contents with spaces" syntax, "" is
  optional when the shell would accept it without quotes.

  First, the simet-ma.conf file in libdir is read.  Then, any .conf files
  inside the conf.d directory are read, in locale order.  Then, the one in
  sysconfdir is read if it exists.  The last definition for each variable
  "wins".

  The config files are not to be modifiable by the same user that runs
  the SIMET suite (unless it is running as root, which is also not
  advised).

  WARNING: modifying the paths is almost always unsafe: system integration
  may break (such integration is outside the scope of these config files).

## API version

  The full agent version (e.g. simet-ma/<version>) is available
  by reading file $AGENT\_VERSION\_FILE.

  The simet-ma build may also hardcode the version wherever required
  as a build-time constant.

## TOKEN and LMAP AGENT-ID API

  The agent token, required to authorize with SIMET2 services, will
  be retrieved and refreshed by simet\_register\_ma.sh.

  *  The agent token will be stored in $AGENT\_TOKEN\_FILE
  *  The LMAP agent-id will be stored in $AGENT\_ID\_FILE

  The simet\_register\_ma.sh script can be called at any time, so all reads
  from the above files must be atomic *or* must flock($AGENT\_TOKEN\_LOCK)
  in shared mode (reading) or exclusive mode (writing).  This lock protects
  both $AGENT\_TOKEN\_FILE and $AGENT\_ID\_FILE.

  If either file is missing, measurements are *NOT* to be carried out.

  Beware of file system permission issues if you call these scripts as
  different users (e.g. "root" and "nicbr-simet").

### Access to measurement results

  Access to measurement results and reports is done using the _agent-id_
  and _view-results token_.  The agent token is not used.

  The _view-results token_ is changed every time simet\_register\_ma.sh is
  run to refresh tokens and credentials, typically this should be done once
  every 24h.

  The simet\_view\_results.sh script can be used to open a device-results
  page on the web browser, using the above tokens.  It can also take
  an "--url" parameter to just output the full URL to the results page.

### MA pairing recovery mode

  The SIMET2 API might, for several reasons, refuse the current
  registration credentials of the MA, such as:

  1. MA has corrupted, outdated, or blacklisted credentials

  2. Software bug in the MA side rendered the credentials invalid somehow

  3. SIMET2 server-side issues are not allowing the web API to properly
     validate the credentials (potentially creating a fleet-wide issue)

  When that happens, the MA will attempt to create a new identity for
  itself, as an automated healing strategy.  This new identity will be
  "anonymous" (not paired to any participant in the web portal).

  As this new identitiy is unpaired, any new measurements made won't be
  visible to any participant [until the MA gets paired again].  The MA's
  measurement result page will also lose access to any measurements made by
  the MA's previous identity.

  The MA can then resume all measurements using the new identity /
  credentials.  Should its new identity/credentials be paired, all such
  measurements become visible to the participant that paired with the MA.

  If the MA was in a paired state when it got its credentials refused, it
  should enter identity recovery mode for two weeks, or until it gets
  paired to a participant, whichever happens first.  Recovery mode
  consists into an extra API call that offers information useful for
  automated re-pairing, but it is expected to succeed only if the SIMET
  team has deployed an strategy for disaster recovery due to an issue on
  the server-side.

  Pairing recovery mode is automatically handled by simet\_register\ma.sh.

  Measurement Agents of the "embedded" class, when appropriate support for
  a device-persistent ID that survives factory-reset / full reinstall is
  present, are eligible for automated identity recovery.  In that case, the
  MA will receive an updated version of its previous identity and tokens,
  and will recover previous pairing and measurement history.

## Virtual Label API, agent pairing

  Each MA should have a virtual label that is used to help the user give
  "proof of possession" of a MA to the SIMET2 portal, in a procedure we
  call "MA and participant pairing" (or "pairing" for short).

  For this to work safely, it must be impossible for anyone not in
  possession of a device to calculate or otherwise obtain its virtual
  label.  This includes anyone sniffing wireless traffic or network
  traffic (of *any sort*) of that device.

  Virtual labels must not be used for anything else than the attachment
  participant, and they must not allow someone to calculate the factory
  default passwords and credentials from the contents of the virtual
  label.

  The virtual label *must* be unique, much like MAC addresses, but it must
  not be a function of a MAC address that can be derived from the MAC
  address of any radios, or from any other remotely accessible
  information.

  Users will be informed they are being denied pairing funcionality due to
  a device defect should they attempt to pair to a blacklisted device.  We
  may blacklist all devices of a vendor that share the same SIMET2 engine
  when we are made aware of a violation of the SIMET2 requirements for MAs
  or any such rules.  The vendor must contact us to get the blacklisting
  reduced to the exact set of affected devices, and we only accepted a
  device as fixed for unblacklisting purposes, after a *proper*,
  permantent fix is deployed.  The vendor will have to fully disclose the
  fix to us.

  On dedicated MA devices like a SIMETBOX, the SIMET virtual label will
  often be printed on a physical label attached to the device, to allow
  no-device-interaction setup.  In this case, the virtual label *must not
  change* from what is printed on the physical label -- often requiring a
  vital product data area in FLASH that does not get changed by firmware
  updates, and factory-resets, where the virtual label will be stored
  at manufacture/label printing time.

  Some MA devices can easily expose the virtual label to the user through
  an LCD display or some other UI that the user is forced to go through
  for the device to be usable in the first place (i.e. it cannot work "out
  of the box" without the user accessing its UI, due to factors completely
  unrelated to the virtual label).  In that case the virtual label can
  change with firmware updates and when the device is subject to a factory
  reset, and the user should get its contents through that UI -- but there
  should be no physical label with its content in this case, since it can
  change.

  * The agent will "cache" its virtual label in $AGENT\_VLABEL\_FILE

  The simet\_create\_vlabel.sh script takes care of generating a virtual
  label with the required persistence (e.g. by retrieving it from FLASH)
  and storing it in the "cache" file.  It must not never change a virtual
  label.

  The simet\_read\_vlabel.sh script outputs the virtual label to stdout.

### Pairing flow

  1. The device must be in an "unpaired" state to attempt pairing.
     Already paired devices are not to attempt pairing (it will be
     rejected).

  2. The device will offer itself up for pairing only if unpaired,
     typically when it is registering for the first time, or updating
     its registration information.

     The MA may withdraw its availability for pairing at any time, as
     long as it is still unpaired.  It may also request itself to be
     detached from any pairings.

     The MA may have an UI trigger a pairing attempt (it just needs to
     trigger an registration information update); to request to be
     detached from any pairing; to display pairing information; and to
     toggle whether it is available for pairing on the SIMET2 portal, or
     not.

  3. Pairing happens as soon as both an MA and a participant with
     matching virtual labels (augmented by the SIMET2 engine name) are
     available for pairing at the same time.

  4. When a SIMET2 participant requests that a MA with a matching virtual
     label and SIMET engine be paired with it, the pairing will happen if
     the MA has already announced itself as available for pairing.

     Accordingly, an MA may be immediately paired to a participant if the
     participant had already requested the pairing, and the MA announces
     itself as available for pairing.

  Note: both the MA and the participant may remove a pending pairing
  offer/request.  On the MA side, this is an optional feature.

  Note: pairing requests and pairing offers remain open for a long time,
  typically three months, unless explicitly removed.

  On simet-ma, one has to call "simet\_create\_vlabel.sh" once when the
  software is installed (or after a factory reset).  To render the MA
  unavailable for pairing, set the virtual label to DISABLED (all caps)
  or to an empty value.

  To update the virtual label and pairing availability, run
  "simet\_register\_ma.sh".

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
  capabilities will be refused with a warning (schedule is still to be
  accepted).

  There are a few "general" capabilities and/or programs that MUST be
  available, these are documented by the hardcoded capabilities of
  simet-ma.  They are all prefixed by "simet.nic.br\_".

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

  While in traditional LMAP the MA would start without an agent-id and
  get one from the controller, SIMET2 requires prior registering through
  REST API calls and provisions an agent-id at that time.  The SIMET2
  controller will not attempt to change a MA's agent-id.

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

### LMAP MA CAPABILITIES:

  The MA must announce these tags in its capabilities to the SIMET2
  controller:

  - system-ipv4-capable -- system has IPv4 enabled in its IP stack
  - system-ipv6-capable -- system has IPv6 enabled in its IP stack
  - simet.nic.br\_engine-name:< registered simet engine id >
  - simet.nic.br\_engine-version:< simet engine version >

  All hardcoded and default tasks must have their "name", "version" and
  "program" fields set to meaningful values.  They are _not_ to be
  considered optional on SIMET2 MAs.

  IPv6 support is mandatory.

  Non-registered SIMET engines are not allowed to connect to the SIMET2
  production servers.

## LMAP runner API

  Please refer to simet-lmapd documentation for the conventions used by
  simet-lmapd when it is running a program (task).

  Basically, only JSON is used (not XML), and tasks must output their
  results in the same format as ietf-lmap-report::result:table, to be
  merged into a single report by "lmapctl report".  There is a
  convention for status exit codes as well, which should be followed
  when possible.

### SIMET LMAP task tags

  There are a few SIMET2 tags that should be set on the hardcoded and
  default tasks.

  FIXME: update this
  - simet-engine:< registered simet engine id >
  - task-version:< version of the program/package that executes the task >
    (this is usually the same as the SIMET engine version)
  - task-program:< name of the program that is executed by the task >
  - exit-status-urn:< URN identifying the exit status table >
  - simet.nic.br-test:<tag>  --  causes a report to be destroyed upon
    reception by the SIMET2 production LMAP collectors.  Used to aid
    development and testing on instrumented development collectors.

  MAs running development code must set the tag
  "simet.nic.br-test:devel" on all tasks, unless they belong to NIC.br
  public IP address space (for which such tag is enforced by the
  collectors themselves).


## Locks (misc)
  $AGENT\_LOCK  -  runner/scheduler lock.  Protects a measurement run.
     take the shared lock to block measurements, take the exclusive
     lock to measure.

  $AGENT\_TOKEN\_LOCK   -  general config lock.  Protects agent-id,
     agent token, LMAP config, and so on.  Take the exclusive lock
     when doing a non-atomic update.

  Locks are empty files, locked using flock(2).  Beware permission
  issues with the lock directory and lock files when scripts are run
  with different privilege levels (e.g. root and a non-privileged user).


## Hooks

  Some of the API scripts (in shell) have (shell) hooks, or can have its
  internal functions replaced (via functions named FUNCTION\_override).

  Hooks are highly integrated with the script, you usually need to
  manipulate local variables, etc.  As such, please read the script to
  know what hooks are available.

  The hook implementation is provided by simet\_lib.sh.

### simet\_register\_ma.sh

  <libdir>/simet/simet\_register\_ma-hooks.sh
  <sysconfdir>/simet/simet\_register\_ma-hooks.sh

  Hook availability is often reduced in SIMETBox builds, we recommend
  checking the source code.

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
  legacy SIMET API with geolocation data.  It will be phased out and
  removed when we disable the legacy API.  The legacy script uses
  simet\_geolocation.sh to do the real work.
