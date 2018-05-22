# generate a single executable script "lmap_schedule_574.sh"
# copy deployment artifacts to ./dist
.PHONY: simet
simet:
	mkdir -p 													 ./dist/bin ./dist/conf
	rm -fr 														 ./dist/bin/* ./dist/conf/*
	touch 												     ./dist/bin/lmap_schedule_574.sh
	cat ./vendor/sempl							>> ./dist/bin/lmap_schedule_574.sh
	cat ./task_discovery.sh			 		>> ./dist/bin/lmap_schedule_574.sh
	cat ./task_authentication.sh 		>> ./dist/bin/lmap_schedule_574.sh
	cat ./task_report.sh 						>> ./dist/bin/lmap_schedule_574.sh
	cat ./schedule_574.sh  					>> ./dist/bin/lmap_schedule_574.sh
	chmod a+x													 ./dist/bin/lmap_schedule_574.sh
	cp ./schedule_574.conf 						 ./dist/conf/lmap_schedule_574.conf
	cp ./discovery.response 					 ./dist/conf/lmap_schedule_574.discovery.response
	cp ./report.template 							 ./dist/conf/lmap_schedule_574.report.template
