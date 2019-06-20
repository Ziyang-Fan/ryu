'''
                |--------switch2 --------|
   host1 --- switch1                     switch4 ----host3
   host2 ----|  |                        |     |--------host4
                -------- switch3 ---------
'''

from mininet.topo import Topo
from mininet.link import TCLink

class MyTopo(Topo):
    "simple loop topology example"

    def __init__(self):
        "Create custom loop topo."

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        s1 = self.addSwitch("s1", protocols='OpenFlow13')
        s2 = self.addSwitch("s2", protocols='OpenFlow13')
        s3 = self.addSwitch("s3", protocols='OpenFlow13')
        s4 = self.addSwitch("s4", protocols='OpenFlow13')
        s5 = self.addSwitch("s5", protocols='OpenFlow13')

        s6 = self.addSwitch("s6", protocols='OpenFlow13')
        s7 = self.addSwitch("s7", protocols='OpenFlow13')
        s8 = self.addSwitch("s8", protocols='OpenFlow13')


        # links
        self.addLink(s1, h1, cls=TCLink, bw=100)
        self.addLink(s1, s2, cls=TCLink, bw=10)
        self.addLink(s1, s3, cls=TCLink, bw=10)
        self.addLink(s2, s4, cls=TCLink, bw=10)
        self.addLink(s3, s4, cls=TCLink, bw=10)
        self.addLink(s4, s5, cls=TCLink, bw=10)
        self.addLink(s5, s6, cls=TCLink, bw=10)
        self.addLink(s5, s7, cls=TCLink, bw=10)
        self.addLink(s6, s8, cls=TCLink, bw=10)
        self.addLink(s7, s8, cls=TCLink, bw=10)
        self.addLink(s8, h2, cls=TCLink, bw=100)

topos = {'mytopo': (lambda: MyTopo())}
