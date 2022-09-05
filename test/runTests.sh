#!/bin/bash
docker-compose -f docker-compose.test.yml up --detach
echo "wait for db to setup"
sleep 20
go test -run MatchCPEs
go test -run FindValuableEntries
go test -run Api
docker-compose -f docker-compose.test.yml down