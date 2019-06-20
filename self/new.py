'''
cost = []
MAX_PATHS = 2
all_paths = [[2, 3, 4], [4, 5, 6], [2, 3, 4, 5, 6], [4]]
for i in all_paths:
    cost.append(len(i))
paths_count = len(all_paths) if len(all_paths) < MAX_PATHS else MAX_PATHS
a = sorted(all_paths, key=lambda x: len(x))[0:(paths_count)]
print(a)
s_paths = [['d', 2, 3, 4,'f'], ['d', 4, 5, 6,'g']]
b = set().union(*s_paths)
print(b)

weight = 2
sum = 5
print(int(round((1 - 2 / 5) * 10)))
'''
'''
import matplotlib.pyplot as plt
import networkx as nx

G = nx.Graph()

G.add_edge('a', 'b', weight=0.6)
G.add_edge('a', 'c', weight=0.2)
G.add_edge('c', 'd', weight=0.1)
G.add_edge('c', 'e', weight=0.7)
G.add_edge('c', 'f', weight=0.9)
G.add_edge('a', 'd', weight=0.3)

elarge = [(u, v) for (u, v, d) in G.edges(data=True) if d['weight'] > 0.5]
esmall = [(u, v) for (u, v, d) in G.edges(data=True) if d['weight'] <= 0.5]

pos = nx.spring_layout(G)  # positions for all nodes

# nodes
nx.draw_networkx_nodes(G, pos, node_size=700)

# edges
nx.draw_networkx_edges(G, pos, edgelist=elarge,
                       width=6)
nx.draw_networkx_edges(G, pos, edgelist=esmall,
                       width=6, alpha=0.5, edge_color='b', style='dashed')

# labels
nx.draw_networkx_labels(G, pos, font_size=20, font_family='sans-serif')

plt.axis('off')
plt.show()
'''

'''
from collections import defaultdict

ports = defaultdict(list)
ports[1]=4
print (ports)
'''
'''
from collections import defaultdict
ports = defaultdict(list)

ports[0].append((2,3))
ports[0].append((4,5))
print (ports)
'''
topos_to_benchmark = {
    'default': {
                'topo': 'default_multipath',
                'best_case': 1,
                'worst_case': 2,
                'watch_switch': 's5',
                'ports': [1, 2]
            },
    'data_centre': {
                'topo': 'data_centre_multipath',
                'best_case': 0,
                'worst_case': 5,
                'watch_switch': 's5',
                'ports': [1, 2, 3]
            },
    'default_no_limit': {
                'topo': 'default_no_limits',
                'best_case': 1,
                'worst_case': 2,
                'custom_n_hop': 'n_hop_case_no_limits',
                'watch_switch': 's5',
                'ports': [1, 2]
            }
        }

print(topos_to_benchmark)
print(topos_to_benchmark['default']['best_case'])