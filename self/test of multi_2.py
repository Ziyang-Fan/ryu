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

#
#

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.ofproto import ether
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu import utils
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
import random
import networkx as nx
from collections import defaultdict


class ExampleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ExampleSwitch13, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.switch_mac_port = {}
        self.datapaths = {}
        # self.FLAGS = True
        self.nodes = {}
        self.links = {}
        self.net = nx.Graph()
        self.mac_ipv4 = []
        self.switches = []  # DPID[1,2,3]
        # self.switch_topo[s1][s2] = port from s1 to s2
        self.switch_topo = defaultdict(dict) # {dpid :{dpid / mac: out_port },}
        # Trackers for grouping paths
        self.multipath_group_ids = {}   # [(switch, start_n, end_n)] = id
        self.group_ids = []             # all id's used in multipath_group_ids
        # self.datapath_list[switch.id] = switch = ev.switch.dp.id
        self.datapath_list = {}
        self.hostmac_to_dpid = {}

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
        self.add_flow(datapath,0, match, actions)
        self.logger.info("switch:%s connected", dpid)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
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

    # may can merge with send_out
    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        actions = []
        parser = datapath.ofproto_parser
        if dst_port:
            actions.append(parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  data=msg_data, in_port=src_port,
                                  actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def flood(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                     ofproto.OFPP_CONTROLLER,
                                     ofproto.OFPP_FLOOD, msg.data)
        datapath.send_msg(out)
        self.logger.debug("Flooding msg")

    def arp_forwarding(self, msg, src_ip, dst_ip, eth_pkt):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        out_port = self.switch_mac_port[datapath.id].get(eth_pkt.dst)
        if out_port is not None:
            match = parser.OFPMatch(in_port=in_port, eth_dst= eth_pkt.dst,
                                    eth_type=eth_pkt.ethertype)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 2, match, actions)
            self.send_packet_out(datapath, msg.buffer_id, in_port,
                                 out_port, msg.data)
            self.logger.debug("Reply ARP to knew host")
        else:
            self.flood(msg)

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

        if eth.ethertype == 35020:
            return

        if isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")

            if self.mac_learning(dpid, src, in_port) is False:
                self.logger.debug("ARP packet enter in different ports")
                return
            # make mac_ipv4 dict
            if src != "ff:ff:ff:ff:ff:ff" and dst != "ff:ff:ff:ff:ff:ff":
                if src not in self.mac_ipv4:
                    self.mac_ipv4[src] = arp_pkt.src_ip
                if dst not in self.mac_ipv4:
                    self.mac_ipv4[dst] = arp_pkt.dst_ip
            # print self.mac_ipv4
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip, eth)

        if isinstance(ip_pkt, ipv4.ipv4):
            self.logger.debug("IPV4 processing")
            mac_to_port_table = self.switch_mac_port.get(dpid)
            if mac_to_port_table is None:
                self.logger.info("Dpid is not in mac_to_port")
                return

            if src not in self.net:  # Learn it
                self.net.add_node(src)  # Add a node to the graph
                # Add a link from the node to it's edge switch
                self.net.add_edge(dpid, src)
                self.hostmac_to_dpid[src] = dpid # record the link host to dpid

            if dst in self.net:
                all_paths = []
                all_paths = self.get_all_paths(src, dst)
                out_port_list = self.get_path_port(src, dpid, dst, all_paths)
                if len(out_port_list) == 1:
                    actions = [parser.OFPActionOutput(out_port_list[0])]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst,
                                            eth_type=eth.ethertype)
                    self.add_flow(datapath, 1, match, actions)
                    self.send_packet_out(datapath, msg.buffer_id, in_port,
                                         out_port_list[0], msg.data)
                elif len(out_port_list) > 1:

                    # 写一个def安装group


            else:
                if self.mac_learning(dpid, src, in_port) is False:
                    self.logger.debug("IPV4 packet enter in different ports")
                    return
                else:
                    self.flood(msg)

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
            del self.adjacency[switch]
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

    def get_all_paths(self,src, dst):
        # [[2,3,4,],[4,5,6]]
        all_paths = list(
            nx.node_disjoint_paths(self.net,
                                   self.hostmac_to_dpid[src],
                                   self.hostmac_to_dpid[dst]))
        return all_paths

    # return the out_port
    def get_path_port(self, src, dpid, dst, all_paths):
        out_port_list = []
        if self.hostmac_to_dpid[src] != self.hostmac_to_dpid[dst]:
            if all_paths:
                for paths in all_paths:
                    paths.append(dst)
                    paths.insert(0, src)

            out_port_list = []
            if len(all_paths) == 1:
                best_path_list = all_paths
            else:
                best_path_list = self.get_best_paths(all_paths)
            for best_path in best_path_list:
                if dpid in best_path:
                    next_hop = best_path[best_path.index(dpid) + 1]
                    out_port_list.append(self.switch_topo[dpid][next_hop])
                    return out_port_list

        elif dst in self.switch_mac_port[dpid]:
            out_port_list.append(self.switch_mac_port[dpid][dst])
            return out_port_list
        else:
            return out_port_list
            # print "*********{}to{}*******".format(self.mac_ipv4[src],
            # (link to last line)self.mac_ipv4[dst])
            # if all_paths != 0: print all_paths

    # by hop return [[2]] or [[2, 3], [2, 4]]
    def get_best_paths(self, all_paths):
        cost = []
        max_num = 2  # num of mutiple-paths
        for i in all_paths:
            cost.append(len(i))
        count = len(all_paths) if len(all_paths) < max_num else max_num
        best_paths = sorted(all_paths, key=lambda x: len(x))[0:count]
        return best_paths

    def generate_openflow_gid(self):
        """
        Returns a random OpenFlow group id
        """
        n = random.randint(0, 2 ** 32)
        while n in self.group_ids:
            n = random.randint(0, 2 ** 32)
        return n

    def get_group_flows(self, src, dst, all_paths, out_port_list):
        group_id = None
        group_new = False

        switches_in_paths = set().union(*all_paths)

        for dpid in switches_in_paths:
            dp = self.datapath_list[dpid]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            ports = defaultdict(list)
            actions = []

            match_ip = ofp_parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=self.mac_ipv4[src],
                ipv4_dst=self.mac_ipv4[dst]
            )

            out_ports = out_port_list

