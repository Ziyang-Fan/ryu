#!/bin/bash
set -e
function cleanup {
  sudo mn -c
}
trap cleanup EXIT
sudo mn --controller=remote,ip=127.0.0.1 --mac -i 10.1.1.0/24 --switch=ovsk,protocols=OpenFlow13 --custom=./lib/topo.py --topo=default_multipath
