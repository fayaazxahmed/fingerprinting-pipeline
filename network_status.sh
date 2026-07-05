#!/bin/bash

# All 9 containers should show as running
docker ps

# Confirm every IP assignment matches the diagram
docker network inspect iot-sim-net

# Check the observer is capturing live traffic
docker exec observer tcpdump -i eth0 -n --count 20