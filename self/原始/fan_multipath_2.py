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

# achieve multipath find and get best by NO.hops(6.14)


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
from ryu.topology.api import get_switch, get_link, get_host
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
import networkx as nx
from collections import defaultdict
import copy


class ExampleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ExampleSwitch13, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.switch_mac_port = {}
        self.datapaths = {}
        # self.FLAGS = True
        self.topology_api_app = self
        self.nodes = {}
        self.links = {}
        self.net = nx.Graph()
        self.mac_ipv4 = {}
        self.topology_api_app = self
        self.switches = []  # DPID[1,2,3]
        # self.switch_topo[s1][s2] = port from s1 to s2
        self.switch_topo = defaultdict(dict)
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
        self.add_flow(datapath, 0,0, match, actions)
        self.logger.info("switch:%s connected", dpid)

    def add_flow(self, datapath, hard_timeout, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                hard_timeout=hard_timeout,
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
            self.add_flow(datapath, 0, 2, match, actions)
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

            if self.mac_learning(dpid, eth.src, in_port) is False:
                self.logger.debug("ARP packet enter in different ports")
                return
            # make mac_ipv4 dict
            if src != "ff:ff:ff:ff:ff:ff" and dst != "ff:ff:ff:ff:ff:ff":
                if src not in self.mac_ipv4:
                    self.mac_ipv4[src] = [arp_pkt.src_ip]
                if dst not in self.mac_ipv4:
                    self.mac_ipv4[dst] = [arp_pkt.dst_ip]
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
                out_port = self.get_path_port(src, dpid, dst)
                if out_port :
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst,
                                            eth_type=eth.ethertype)
                    self.add_flow(datapath, 0, 1, match, actions)
                    self.send_packet_out(datapath, msg.buffer_id, in_port,
                                         out_port, msg.data)
            else:
                if self.mac_learning(dpid, eth.src, in_port) is False:
                    self.logger.debug("IPV4 packet enter in different ports")
                    return
                else:
                    self.flood(msg)

            # print ipv4_switch_path
            '''
            if src in path and dst in path:
                ip_path = copy.deepcopy(path)
                ip_path[0] = self.mac_ipv4[src]
                ip_path[len(ip_path)-1] = self.mac_ipv4[dst]
                print ip_path
            '''
    # networkx-topo
    '''
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology(self, ev):
        switch_id = ev.switch.dp
        switch_list = get_switch(self.topology_api_app, None)
        switches_id = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches_id)
        
        print "**********List of switches"
        for switch in switch_list:
            # self.ls(switch)
            print switch
        
        
        links_list = get_link(self.topology_api_app, None)
        # print links_list
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for
                 link in links_list]
        # print links
        self.net.add_edges_from(links)
        links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for
                 link in links_list]
        # print links
        self.net.add_edges_from(links)
    '''

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

    # return the our_port
    def get_path_port(self, src, dpid, dst):
        out_port = None
        if self.hostmac_to_dpid[src] != self.hostmac_to_dpid[dst]:
            all_paths = []
            all_paths = list(
                nx.node_disjoint_paths(self.net,
                                        self.hostmac_to_dpid[src],
                                        self.hostmac_to_dpid[dst]))
            if all_paths:
                for paths in all_paths:
                    paths.append(dst)
                    paths.insert(0, src)
            best_path = self.get_best_path(all_paths)
            print"**** Best Path {} ---- {} is *****".format(src,dst)
            print best_path
            # print dpid

            if dpid in best_path:
                next_hop = best_path[best_path.index(dpid) + 1]
                out_port = self.switch_topo[dpid][next_hop]
                return out_port
        elif dst in self.switch_mac_port[dpid]:
            out_port = self.switch_mac_port[dpid][dst]
            return out_port
        else: return out_port
            # print "*********{}to{}*******".format(self.mac_ipv4[src],
                                                    # self.mac_ipv4[dst])
            # if all_paths != 0: print all_paths

    # by hop
    def get_best_path(self, all_paths):
        cost = []
        for paths in all_paths:
            cost.append(len(paths))
            # return the first min hops'path
        return all_paths[cost.index(min(cost))]