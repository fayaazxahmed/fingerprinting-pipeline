#!/bin/bash

echo "Setting up Docker network"
bash docker/setup/bridge_network.sh
bash docker/setup/shared_service.sh