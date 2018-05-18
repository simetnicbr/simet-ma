# lmap_shell_tasks

- Orchestrate the measurement and reporting of Simet's canocical metrics (Anatel 574).
- Used while the lmap_scheduler isn't available.
- Orchestration
  - 1. task_discovery
  - 2. task_authentication
  - 3. task_twamp
  - 4. task_tcp
  - 5. task_report
- Configuration
  - .dist/lmap_schedule_574.conf (configuration for an individual SimetBox)
  - .dist/discovery.response (temporary configuration while mocking API "server-list")
- An LMAP Report is pushed to the given LMAP Collector, as the script's final result.

## Build

```sh
make simet
```

## Execution

```sh
# A) via cron
echo "1 */3 * * * /usr/local/bin/lmap_schedule_574.sh --config /etc/simet/lmap_schedule_574.conf" | crontab -

# B) manual execution
# Requires files in relative location:
#   script and config in ./dist
#   mocks (tcp, twamp) in ./mock
#   execution from .
./dist/bin/lmap_schedule_574.sh --config ./dist/conf/lmap_schedule_574.conf
```

## Test scripts in isolation

```sh
# discovery
./task-discovery --endpoint ./response.discovery.json
./tast-discovery --endpoint https://api.simet.nic.br/services/server_list

# authentication
./task_authentication --endpoint https://docker.lab.simet.nic.br/measure/jwt --agent aba55dac-6397-4027-a679-cab5e73680e5

# report
./task-report \
  --template ./report.template \
  --agent aba55dac-6397-4027-a679-cab5e73680e5 \
  --tabledir /tmp/schedule_574/2018-05-11T21:52:50Z \
  --endpoint https://docker.lab.simet.nic.br:443/collector/measure \
  --jwt abc
```
