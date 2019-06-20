from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.util import dumpNodeConnections
from mininet.cli import CLI
import subprocess as sp
import time
import re
import pprint
import json
import datetime
import os

from mininet.util import (waitListening)

from lib.topo import topos


topo = topos['default_multipath'](n=1)
net = Mininet(topo=topo, controller=RemoteController)

