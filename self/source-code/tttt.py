
'''
cost = []
all_paths = [[2, 3, 4], [6], [4, 5, 6, 7, 8], [1], [3]]
for paths in all_paths:
    cost.append(len(paths))

print(all_paths[cost.index(min(cost))])
'''
'''
best_path = [2, 3, 4, 5]
next_hop = best_path[best_path.index(6) + 1]
print(next_hop)
'''
from collections import defaultdict
DEFAULT_BW = 10000000
bandwidths = defaultdict(lambda: defaultdict(lambda: 10000000))
bandwidths[1][2] = 55555
bandwidths[1][3] = 66666
bandwidths[2][4] = 77777
bandwidths[3][4] = 88888
print(bandwidths[1][2])
print(bandwidths[1][3])