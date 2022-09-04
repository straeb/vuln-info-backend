#!/bin/bash
docker-compose -f docker-compose.test.yml up --detach
go test
docker-compose -f docker-compose.test.yml down


