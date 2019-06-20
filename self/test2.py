import networkx as nx

import matplotlib.pyplot as plt


class Example():

    def __init__(self, *args, **kwargs):

        self.mac_to_port = {}

        self.datapaths = {}

        self.FLAGS = True

        self.topology_api_app = self

        self.nodes = {}

        self.links = {}

    def get_topology(self):

        net = nx.DiGraph()
        print("2")
        switches = [1, 2, 3]

        net.add_nodes_from(switches)

        return net

    def ff(self):
        net = self.get_topology()
        print("1")
        nx.draw(net)
        plt.show()

if __name__ == '__main__':
    Example().get_topology()
    Example().ff()
    Example.ff()