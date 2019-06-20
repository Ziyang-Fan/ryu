from mininet.topo import Topo
from mininet.link import TCLink


class MyTopo(Topo):
    '''
    This is the default multipath topology to represent a simple Multipath
    topology
    '''

    def __init__(self):
        """Builds the current topology defined below

        This method is overriding Topo.build()

        Parameters
        ----------


        Returns
        -------
        None
            None

        """
	Topo.__init__(self)
        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        s1 = self.addSwitch("s1", protocols='OpenFlow13')
        s2 = self.addSwitch("s2", protocols='OpenFlow13')
        s3 = self.addSwitch("s3", protocols='OpenFlow13')
        s4 = self.addSwitch("s4", protocols='OpenFlow13')
        s5 = self.addSwitch("s5", protocols='OpenFlow13')

        # links
        self.addLink(s1, h1, cls=TCLink, bw=100)
        self.addLink(s1, s2, cls=TCLink, bw=10)
        self.addLink(s1, s3, cls=TCLink, bw=10)
        self.addLink(s2, s4, cls=TCLink, bw=10)
        self.addLink(s3, s5, cls=TCLink, bw=10)
        self.addLink(s4, s5, cls=TCLink, bw=10)
        self.addLink(s5, h2, cls=TCLink, bw=100)

        # Watch switch 5, ports: 1, 2

topos = {'mytopo': (lambda: MyTopo())}

 
