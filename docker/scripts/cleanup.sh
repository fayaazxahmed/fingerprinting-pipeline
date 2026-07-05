#!/bin/bash

# Stop and remove all containers
docker stop $(docker ps -aq)
docker rm $(docker ps -aq)