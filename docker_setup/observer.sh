#!/bin/bash
docker run -d \
  --name observer \
  --network iot-sim-net \
  --ip 192.168.10.100 \
  --cap-add NET_ADMIN \
  -v $(pwd)/captures:/captures \
  nicolaka/netshoot \
  tcpdump -i eth0 -w /captures/traffic.pcap