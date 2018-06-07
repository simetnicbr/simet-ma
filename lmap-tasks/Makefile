# make target exposed to dependent project simet-agent-unix
# 	- generate a single executable script "lmap_schedule_574.sh"
# 	- copy deployment artifacts to ./dist
simet: prod

prod: configless
	cp ./conf/prod/schedule_574.conf	./dist/conf/lmap_schedule_574.conf
	cp ./conf/prod/discovery.response ./dist/conf/lmap_schedule_574.discovery.response

dev: configless
	cp ./conf/dev/schedule_574.conf 	./dist/conf/lmap_schedule_574.conf
	cp ./conf/dev/discovery.response  ./dist/conf/lmap_schedule_574.discovery.response

.PHONY: configless
configless:
	mkdir -p 												 ./dist/bin ./dist/conf
	rm -fr 													 ./dist/bin/* ./dist/conf/*
	touch 											     ./dist/bin/lmap_schedule_574.sh
	cat ./src/vendor/sempl						>> ./dist/bin/lmap_schedule_574.sh
	cat ./src/task_discovery.sh			 	>> ./dist/bin/lmap_schedule_574.sh
	cat ./src/task_authentication.sh	>> ./dist/bin/lmap_schedule_574.sh
	cat ./src/task_report.sh 					>> ./dist/bin/lmap_schedule_574.sh
	cat ./src/schedule_574.sh  				>> ./dist/bin/lmap_schedule_574.sh
	chmod a+x												 ./dist/bin/lmap_schedule_574.sh
	cp ./src/report.template 				 ./dist/conf/lmap_schedule_574.report.template

docker-build:
	docker build . -t simet-agent-lmap-tasks-dev-image

docker-run:
	echo $(pwd)
	docker run -it --rm --mount type=bind,src="/Users/holger/git-repos/simet2/simet-agent-lmap-tasks",dst="/home" simet-agent-lmap-tasks-dev-image
