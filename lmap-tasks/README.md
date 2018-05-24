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

## Interactive Development & Execution

While executing './dist/bin/lmap_schedule_574.sh' inside the container,
the executable may be rebuild on the host machine with 'make simet'.

```sh
# initial build & setup of dev container
make dev
make docker-build
make docker-run

# A) execute the whole script, as distributed for deployment, inside the container
container> /bin/ash ./dist/bin/lmap_schedule_574.sh --config ./dist/conf/lmap_schedule_574.conf 
# with tracing (+x)
container> /bin/ash +x ./dist/bin/lmap_schedule_574.sh --config ./dist/conf/lmap_schedule_574.conf  

# B) execute a single task script inside the container

# discovery
container> /bin/ash ./src/task_discovery.sh --endpoint ./conf/dev/discovery.response
# Today webservice 'https://api.simet.nic.br/services/server_list' is still not deployed.
container> /bin/ash ./src/tast_discovery.sh --endpoint https://api.simet.nic.br/services/server_list 

# authentication
container> /bin/ash ./src/task_authentication.sh --endpoint https://docker.lab.simet.nic.br/measure/jwt --agent aba55dac-6397-4027-a679-cab5e73680e5

# reporting
# supply the required files (mock test results)
container> mkdir -p /tmp/schedule_574/2018-05-24T16:58:59Z 
container> echo "{}" > /tmp/schedule_574/2018-05-24T16:58:59Z/tcp.json
container> echo "{}" > /tmp/schedule_574/2018-05-24T16:58:59Z/twamp.json
conteiner> /bin/ash ./src/task_report.sh \
  --template ./src/report.template \
  --agent aba55dac-6397-4027-a679-cab5e73680e5 \
  --tabledir /tmp/schedule_574/2018-05-24T16:58:59Z \
  --endpoint https://docker.lab.simet.nic.br:443/collector/measure \
  --jwt abc
# HTTP Post will return '401 Unauthorized', as the JWT token 'abc' is fake
# remove the generated report, before re-executing the script
container> rm -f /tmp/schedule_574/2018-05-24T16:58:59Z/_report.json
```
