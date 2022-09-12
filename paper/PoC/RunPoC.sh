#!/bin/bash
#Set up empty test DB
docker-compose -f ../../test/docker-compose.test.yml up --detach
echo "Wait for DB to setup"
sleep 20
echo "Run PoC"
go test -run PoC > poclog.txt
docker-compose -f ../../test/docker-compose.test.yml down