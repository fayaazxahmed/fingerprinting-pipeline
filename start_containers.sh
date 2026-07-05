#!/bin/bash

echo "Setting up benign IoT device containers"
bash docker/setup/tcp_device.sh
bash docker/setup/udp_device.sh

echo "Setting up hostile/compromised device containers"
bash docker/setup/hostile_port_scanner.sh
bash docker/setup/hostile_flooder.sh
bash docker/setup/compromised_device.sh

bash docker/setup/observer.sh