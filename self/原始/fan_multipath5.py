# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# changer the way find path , just a try , can work ,not a useful version 6.20


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.topology import event, switches
import networkx as nx
from collections import defaultdict
import random
import time

REFERENCE_BW = 10000000

DEFAULT_BW = 10000000

MAX_PATHS = 2


class ExampleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ExampleSwitch13, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.switch_mac_port = {}  # self.switch_mac_port[dpid][src]= outport
        # self.FLAGS = True
        self.net = nx.Graph()
        self.arp_table = {}  # match ipv4 to src
        self.switches = []  # DPID[1,2,3]
        # self.switch_topo[s1][s2] = port from s1 to s2
        self.switch_topo = defaultdict(dict)
        # self.datapath_list[switch.id] = switch = ev.switch.dp.id
        self.datapath_list = {}
        self.hostmac_to_dpid = {}
        self.hosts = {}
        self.multipath_ids = {}  # [(switch, start_n, end_n)] = id
        self.group_ids = []
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: DEFAULT_BW))


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        dpid = datapath.id
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("switch:%s connected", dpid)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # print "Adding flow ", match, actions
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def mac_learning(self, dpid, src_mac, in_port):
        self.switch_mac_port.setdefault(dpid, {})
        if src_mac in self.switch_mac_port[dpid]:
            if in_port != self.switch_mac_port[dpid][src_mac]:
                return False
        else:
            self.switch_mac_port[dpid][src_mac] = in_port
            self.switch_topo[dpid][src_mac] = in_port
            return True

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        computation_start = time.time()
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        dst = pkt.get_protocol(ethernet.ethernet).dst
        src = pkt.get_protocol(ethernet.ethernet).src

        if src not in self.net:  # Learn it
            self.net.add_node(src)  # Add a node to the graph
            # Add a link from the node to it's edge switch
            self.net.add_edge(dpid, src)
            self.hostmac_to_dpid[src] = dpid  # record the link host to dpid
            self.hosts[src] = (dpid, in_port)
        '''
        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)
        '''
        if eth.ethertype == 35020:
            return

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        out_port = datapath.ofproto.OFPP_FLOOD


        if isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")

            if self.mac_learning(dpid, src, in_port) is False:
                self.logger.debug("ARP packet enter in different ports")
                return
            # print self.mac_ipv4

            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                h1 = self.hosts[src]
                h2 = self.hosts[dst]
                out_port = self.install_paths(h1[0], h2[0], h2[1], src_ip,
                                              dst_ip)
                self.install_paths(h2[0], h1[0], h1[1], dst_ip, src_ip)
                # reverse
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]
                    out_port = self.install_paths(h1[0], h2[0], h2[1], src_ip,
                                                  dst_ip)
                    self.install_paths(h2[0], h1[0], h1[1], dst_ip, src_ip)
                    # reverse

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
        print "Path installation finished in ", time.time() - computation_start

    # build topology
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser

        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch
            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)
        # bulid switch in networkx
        if switch.id not in self.net:
            self.net.add_node(switch.id)

    # del switch
    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        print ev
        switch = ev.switch.dp.id
        if switch in self.switches:
            self.switches.remove(switch)
            del self.datapath_list[switch]
            del self.switch_topo[switch]
        if switch in self.net:
            self.net.remove_node(switch)

    # add link
    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        self.net.add_edge(s2.dpid, s1.dpid)
        self.switch_topo[s1.dpid][s2.dpid] = s1.port_no
        self.switch_topo[s2.dpid][s1.dpid] = s2.port_no

    # del link
    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        # Exception handling if switch already deleted
        try:
            del self.switch_topo[s1.dpid][s2.dpid]
            del self.switch_topo[s2.dpid][s1.dpid]
            self.net.remove_edge(s2.dpid, s1.dpid)
        except KeyError:
            pass

    def get_paths(self, src, dst):
        all_paths = []
        all_paths = list(nx.node_disjoint_paths(self.net, src, dst))
        # print all_paths
        if len(all_paths) > 1:
            return all_paths
        else:
            all_paths = list(nx.shortest_simple_paths(self.net, src, dst))
        return all_paths

    def get_path_cost(self, path):
        """
        Get the path cost
        """
        cost = 0
        for i in range(len(path) - 1):
            p1 = path[i]
            p2 = path[i + 1]
            e1 = self.switch_topo[p1][p2]
            e2 = self.switch_topo[p2][p1]
            bl = min(self.bandwidths[p1][e1], self.bandwidths[p2][e2])
            link_cost = REFERENCE_BW / bl
            cost += link_cost
        return cost

    # return the one or two least cost paths [[5, 4, 3, 1], [5, 2, 1]]
    def get_optimal_paths(self, src, dst):
        """
        Get the n-most optimal paths according to MAX_PATHS
        """
        paths = self.get_paths(src, dst)
        paths_count = len(paths) if len(
            paths) < MAX_PATHS else MAX_PATHS
        # return the two least cost paths [[5, 4, 3, 1], [5, 2, 1]]
        return sorted(paths,
                      key=lambda x: self.get_path_cost(x))[0:paths_count]

    def add_ports_to_paths(self, paths, last_port):
        """
        Add the ports that connects the switches for all paths
        """
        paths_p = []
        #  [{1: (3, 1), 3: (2, 1)}, {1: (2, 1), 2: (2, 1), 4: (2, 1)}]
        #  [{dpid:(in_port, out_port)}]
        for path in paths:
            p = {}
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = self.switch_topo[s1][s2]
                p[s1] = out_port
            p[path[-1]] = last_port
            paths_p.append(p)
        return paths_p

    def generate_openflow_gid(self):
        """
        Returns a random OpenFlow group id
        """
        n = random.randint(0, 2 ** 32)
        while n in self.group_ids:
            n = random.randint(0, 2 ** 32)
        self.group_ids.append(n)
        return n

    def install_paths(self, src_dpid, dst_dpid, last_port, ip_src, ip_dst):
        paths = self.get_optimal_paths(src_dpid, dst_dpid)
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path))
            # print path, "cost = ", pw[len(pw) - 1]
        sum_of_pw = sum(pw) * 1.0
        paths_with_ports = self.add_ports_to_paths(paths, last_port)
        # [{1: 3, 3: 2, 5: 3}, {1: 2, 2: 2, 4: 2, 5: 3}] [{dpid: outport,  }, ]

        switches_in_paths = set().union(*paths)

        j = 0  # match_key
        for switch in switches_in_paths:

            dp = self.datapath_list[switch]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            ports = defaultdict(list)
            # ports[j --- (match_key)] = [(out_port, weight), ..]
            # defaultdict(<type 'list'>, {0: [(3, 2)], 1: [(2, 3)]})

            actions = []
            i = 0
            # path  {1: (1, 3), 3: (1, 2), 5: (1, 3)},
            for path in paths_with_ports:
                if switch in path:
                    out_port = path[switch]
                    port_cost = (out_port, pw[i])
                    if (out_port, pw[i]) not in ports[j]:
                        ports[j].append(port_cost)
                i += 1

            j += 1

            for match_key in ports:
                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=ip_src,
                    ipv4_dst=ip_dst
                )
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806,
                    arp_spa=ip_src,
                    arp_tpa=ip_dst
                )

                out_ports = ports[match_key]
                # print out_ports

                if len(out_ports) > 1:
                    print out_ports
                    group_id = None
                    group_new = False

                    if (switch, src_dpid, dst_dpid) not in self.multipath_ids:
                        group_new = True
                        self.multipath_ids[switch, src_dpid, dst_dpid] \
                            = self.generate_openflow_gid()
                    group_id = self.multipath_ids[switch, src_dpid, dst_dpid]

                    buckets = []
                    # print "node at ",node," out ports : ",out_ports
                    for port, weight in out_ports:
                        bucket_weight = int(
                            round((1 - weight / sum_of_pw) * 10))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                watch_port=port,
                                watch_group=ofp.OFPG_ANY,
                                actions=bucket_action
                            )
                        )

                    if group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id,
                            buckets
                        )
                        dp.send_msg(req)
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                            group_id, buckets)
                        dp.send_msg(req)

                    actions = [ofp_parser.OFPActionGroup(group_id)]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)

                elif len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)
        return paths_with_ports[0][src_dpid]

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        for p in ev.msg.body:
            self.bandwidths[switch.id][p.port_no] = p.curr_speed