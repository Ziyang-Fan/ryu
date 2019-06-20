'''
                |--------switch2 --------|
   host1 --- switch1                     switch4 ----host3
   host2 ----|  |                        |     |--------host4
                -------- switch3 ---------
'''

from mininet.topo import Topo


class MyTopo(Topo):
    "simple loop topology example"

    def __init__(self):
        "Create custom loop topo."

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')

        switch1 = self.addSwitch("s1")
        switch2 = self.addSwitch("s2")
        switch3 = self.addSwitch("s3")
        switch4 = self.addSwitch("s4")

        # Add links
        self.addLink(switch1, host1)
        self.addLink(switch1, host2)
        self.addLink(switch1, switch2)
        self.addLink(switch1, switch3)

        self.addLink(switch2, switch4)
        self.addLink(switch3, switch4)

        self.addLink(switch4, host3)
        self.addLink(switch4, host4)


topos = {'mytopo': (lambda: MyTopo())}
