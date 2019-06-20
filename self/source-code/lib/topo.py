from mininet.topo import Topo
from mininet.link import TCLink


class DefaultMultipath(Topo):
    '''
    This is the default multipath topology to represent a simple Multipath
    topology
    '''

    def build(self):
        """Builds the current topology defined below

        This method is overriding Topo.build()

        Parameters
        ----------


        Returns
        -------
        None
            None

        """

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


class DefaultNoLimits(Topo):
    '''
    This is the static default struct for testing multipath
    It contains 2 nodes which can be accessed via 2 routes
                nodes-routes have varying lengths to them
    This class has consistant speed across lines
    '''

    def build(self):
        """Builds the current topology defined below

        This method is overriding Topo.build()

        Parameters
        ----------


        Returns
        -------
        None
            None

        """
        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        s1 = self.addSwitch("s1", protocols='OpenFlow13')
        s2 = self.addSwitch("s2", protocols='OpenFlow13')
        s3 = self.addSwitch("s3", protocols='OpenFlow13')
        s4 = self.addSwitch("s4", protocols='OpenFlow13')
        s5 = self.addSwitch("s5", protocols='OpenFlow13')

        # links
        self.addLink(s1, h1, cls=TCLink, bw=10)
        self.addLink(s1, s2, cls=TCLink, bw=10)
        self.addLink(s1, s3, cls=TCLink, bw=10)
        self.addLink(s2, s4, cls=TCLink, bw=10)
        self.addLink(s3, s5, cls=TCLink, bw=10)
        self.addLink(s4, s5, cls=TCLink, bw=10)
        self.addLink(s5, h2, cls=TCLink, bw=10)

        # Watch switch 5, ports: 1, 2


class DataCentreMultipath(Topo):
    '''
    This topology represents the base case senario for the Default topology
    '''

    def build(self):
        """Builds the current topology defined below

        This method is overriding Topo.build()

        Parameters
        ----------


        Returns
        -------
        None
            None

        """
        # Add hosts and switches
        s1 = self.addSwitch("s1", protocols='OpenFlow13')

        switches = []  # [0] = s2
        for i in range(0, 5):
            si = self.addSwitch("s{}".format(i + 2), protocols='OpenFlow13')
            self.addLink(s1, si, cls=TCLink, bw=10)
            switches.append(si)
            if i > 0:
                self.addLink(switches[i - 1], si, cls=TCLink, bw=10)

        # Only add 2 host nodes to simplify network
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        self.addLink(switches[1], h1, cls=TCLink, bw=100)
        self.addLink(switches[3], h2, cls=TCLink, bw=100)  # [3] = s5

        # Watch switch 5, ports: 1, 2, 3


class NHopCase(Topo):
    """
    This is a simple topology that connects h1 to s1, h2 to s2 and added as
    many intermediate switches between s1 and s2 as specified in switches
    """

    def build(self, n=0):
        """Builds the current topology defined below

        This method is overriding Topo.build()

        Parameters
        ----------


        Returns
        -------
        None
            None

        """
        self.no_switches = n

        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        s1 = self.addSwitch("s1", protocols='OpenFlow13')
        s2 = self.addSwitch("s2", protocols='OpenFlow13')
        self.addLink(s1, h1, cls=TCLink, bw=100)
        self.addLink(s2, h2, cls=TCLink, bw=100)

        # Link all the intermediate switches
        prevSwitch = s1
        for i in range(0, self.no_switches):
            si = self.addSwitch('s{}'.format(i + 3), protocols='OpenFlow13')
            self.addLink(prevSwitch, si, cls=TCLink, bw=10)
            prevSwitch = si

        # Connect last-added switch to s2
        self.addLink(prevSwitch, s2, cls=TCLink, bw=10)


class NHopCaseNoLimits(Topo):
    """
    This is a simple topology that connects h1 to s1, h2 to s2 and added as
    many intermediate switches between s1 and s2 as specified in switches
    This topology has zero speed limits
    """

    def build(self, n=0):
        """Builds the current topology defined below

        This method is overriding Topo.build()

        Parameters
        ----------


        Returns
        -------
        None
            None

        """
        self.no_switches = n

        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        s1 = self.addSwitch("s1", protocols='OpenFlow13')
        s2 = self.addSwitch("s2", protocols='OpenFlow13')
        self.addLink(s1, h1, cls=TCLink, bw=10)
        self.addLink(s2, h2, cls=TCLink, bw=10)

        # Link all the intermediate switches
        prevSwitch = s1
        for i in range(0, self.no_switches):
            si = self.addSwitch('s{}'.format(i + 3), protocols='OpenFlow13')
            self.addLink(prevSwitch, si, cls=TCLink, bw=10)
            prevSwitch = si

        # Connect last-added switch to s2
        self.addLink(prevSwitch, s2, cls=TCLink, bw=10)


topos = {
    'default_multipath': DefaultMultipath,
    'default_no_limits': DefaultNoLimits,
    'data_centre_multipath': DataCentreMultipath,
    'n_hop_case': NHopCase,
    'n_hop_case_no_limits': NHopCaseNoLimits
}
