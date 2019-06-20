from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event

from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types

from ryu.topology.api import get_switch, get_link

from collections import defaultdict
import random

# Globals
DEFAULT_BW = 10000000  # (~1GBe)

# Ether Protocols
INTERNET_PROTOCOL_V4 = 0x0800
INTERNET_PROTOCOL_V6 = 0x86DD
ADDRESS_RESOLUTION_PROTOCOL = 0x0806
LINK_LAYER_DISCOV_PROTOCOL = 0x88CC

MAX_MULTIPATHS = 2


class MultipathController(app_manager.RyuApp):
    """
    This is a custom controller based on the RYU controller.
    It implements a multipath algorithm to route traffic along a network

    This class is an adapatation and used inspiration from
    Wildan Maulana Syahidillah documentation on implementing a basic mutipath
    algorithm with RYU.

    His source code can be found here:
        https://github.com/wildan2711/multipath/blob/master/ryu_multipath.py

    This application builds ontop of their work by alterning the the flow of
    the application and implmeneting IPv6 in addition to IPv4

    Wildans work has an emphsis on load balancing while this controller is focused
    on increasing the speed and throughput of the network

    Parameters
    ----------
    *args : type
        None
    **kwargs : type
        None

    Attributes
    ----------
    switch_ids : type
        A list of connected switch id's
    switch_links : type
        A 2d dictionary containing directional links between switches
    switch_by_id : type
        a diction that returns a handle to a switch by providing its id
    hosts : type
        an array of hosts
    OFP_VERSIONS : type
        The OpenFlow protocols supported

    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MultipathController, self).__init__(*args, **kwargs)

        # Globals
        self.switch_ids = []        # = [s1.id ... sn.id]
        self.switch_links = {}      # [s1][s2] = port on s1
        self.switch_by_id = {}      # [s1.id] = s1
        self.hosts = {}             # [host] = (dp, port)

        self.arp_table = {}

        # Creates a dict of dicts with default values of DEFAULT_BW
        # Format: [Switch_id][Port] = Bandwidth
        self.bw_by_switch_id = defaultdict(
            lambda: defaultdict(lambda: DEFAULT_BW))

        # Trackers for grouping paths
        self.multipath_group_ids = {}   # [(switch, start_n, end_n)] = id
        self.group_ids = []             # all id's used in multipath_group_ids

        self.max_multipaths = MAX_MULTIPATHS

    # START OF PRIME HELPER FUNCTIONS ##

    # Default flow moficiation structure #!
    def update_flow(self, dp, priority, match, actions, buffer_id=None, debug=False):
        """
        update the flow table of a node (dp) -> this is tthe default struct
        """
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        buffer_id = buffer_id or ofp.OFP_NO_BUFFER

        instructions = [
            ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        flow_modifcation = ofp_parser.OFPFlowMod(datapath=dp, buffer_id=buffer_id,
                                                 priority=priority, match=match,
                                                 instructions=instructions)

        # Send the new/modified flow table to node
        reply = dp.send_msg(flow_modifcation)

        if debug:
            print('Reply from modiication: {}'.format(reply))
            print('With modification: {}'.format(flow_modifcation))

    # Returns known bucket data #!
    def get_bucket_data(self, node, start_node, end_node):
        """
        Returns the data contained for the bucket with
            key: (node, start_node, end_node)
        If one doesn't exist, it will generate a new one
        """
        # Check if multipath has been established
        is_new_group = False
        if (node, start_node, end_node) not in self.multipath_group_ids:
            is_new_group = True
            self.multipath_group_ids[node, start_node,
                                     end_node] = self.generate_random_id()

        group_id = self.multipath_group_ids[node, start_node, end_node]

        return {'id': group_id, 'is_new': is_new_group}

    # Sets flow tables for single and multipath routes #!
    def update_switch_path(self, start_node, end_node, first_port, last_port,
                           start_node_ip, end_node_ip, ipv6=False):
        """
        Update each switch along optimal paths between node1 and node2 with
        new rules on how to forward packets
        """

        # Struct: [{switchi: (start_port, out_port), ..,
        # switchn: (out_port, end_port)}, ...]
        def determine_ports_in_path(paths):
            """
            returns an array of dicts of each node's ports in path
            Struct: [{switch_id: (in_port, out_port)}, ...]
            """
            paths_with_ports = []

            for path in paths:
                path_ports = {}
                in_port = first_port

                for i in range(0, len(path) - 1):
                    node1 = path[i]
                    node2 = path[i + 1]

                    # Get handle on out_port
                    out_port = self.switch_links[node1][node2]
                    # Append port struc for n1-n2 with key n1
                    path_ports[node1] = (in_port, out_port)
                    # Uses out of n1-n2 for in of n2-n3
                    in_port = self.switch_links[node2][node1]

                # Add the last 2 conseq ports
                path_ports[path[-1]] = (in_port, last_port)

                # Append this path_port set to the Array
                paths_with_ports.append(path_ports)

            # Return this data struct
            return paths_with_ports

        # Get a handle on optimal paths
        optimal_paths = self.calc_optimal_paths(start_node, end_node)

        # Used for the buckets later on...
        path_weights = []
        for path in optimal_paths:
            path_weight = self._calc_path_cost(path)
            path_weights.append(path_weight)
            print(path, "cost = ", path_weights[len(path_weights) - 1])

        sum_of_pw = sum(path_weights)

        paths_with_ports = determine_ports_in_path(optimal_paths)

        print('Optiminal Paths: {}'.format(optimal_paths))

        # Falttens optimal paths and creates a unique set
        all_nodes = set().union(*optimal_paths)

        for node in all_nodes:
            # Get a handle on all openflow protocol data
            node_data = self.switch_by_id[node]
            ofp = node_data.ofproto
            ofp_parser = node_data.ofproto_parser

            # Check if we're using IPv4 or IPv6
            ip_eth_type = INTERNET_PROTOCOL_V4
            if ipv6:
                ip_eth_type = INTERNET_PROTOCOL_V6

            # OFP rules to match on:
            match_ip = ofp_parser.OFPMatch(
                eth_type=ip_eth_type,   # Could be IPv4 or IPv6
                ipv4_src=start_node_ip,
                ipv4_dst=end_node_ip)
            match_arp = ofp_parser.OFPMatch(
                eth_type=ADDRESS_RESOLUTION_PROTOCOL,
                arp_spa=start_node_ip,
                arp_tpa=end_node_ip)

            # Make some vars for holding port and action data
            ports = defaultdict(list)  # [in_port] = [(out_port, weight), ..]
            actions = []

            # For each path in all paths (with ports)
            # If this curr node is in the path then make sure its in/out port
            # is documented
            for i, path in enumerate(paths_with_ports):
                if node in path:
                    in_port = path[node][0]
                    out_port = path[node][1]
                    link = (out_port, path_weights[i])
                    if link not in ports[in_port]:
                        ports[in_port].append(link)

            # Now loop over all documented in_ports to generate flow rules
            for in_port in ports:

                out_ports = ports[in_port]
                num_of_out_ports = len(out_ports)

                if num_of_out_ports == 1:
                    # Only a single path from node 1 to node 2
                    out_port = out_ports[0][0]

                    actions = [ofp_parser.OFPActionOutput(out_port)]

                    # Modify flow table to allow packet to flow in dir of path
                    self.update_flow(node_data, 32768, match_ip, actions)
                    self.update_flow(node_data, 1, match_arp, actions)

                elif num_of_out_ports > 1:
                    # Install Multipath algorithm: multiple routes to choose
                    group_data = self.get_bucket_data(
                        node, start_node, end_node)

                    group_id = group_data['id']
                    is_new_group = group_data['is_new']
                    buckets = []

                    # For each link, detmine the oFBucket action
                    for port, weight in out_ports:
                        # Determine the weight of the whole of bucket

                        # Bucket weight = 0-100 value | higher = faster
                        bucket_weight_float = (1 - weight / sum_of_pw) * 100

                        # Append the bucket to the list to send later
                        bucket_weight = int(round(bucket_weight_float))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                watch_port=port,
                                watch_group=ofp.OFPG_ANY,
                                actions=bucket_action
                            )
                        )

                    # Specify bucket modication type
                    ofpgc_type = ofp.OFPGC_MODIFY  # Defaut is to modify
                    if is_new_group:
                        ofpgc_type = ofp.OFPGC_ADD

                    # Build the request
                    req = ofp_parser.OFPGroupMod(
                        node_data, ofpgc_type, ofp.OFPGT_SELECT, group_id,
                        buckets)

                    # Send the new group modification to the node
                    reply = node_data.send_msg(req)  # resp = true if success

                    # Create actions for flow modifications
                    actions = [ofp_parser.OFPActionGroup(group_id)]

                    # Send the new flow entries (for mac ipv4 and mac addr.)
                    self.update_flow(node_data, 32768, match_ip, actions)
                    self.update_flow(node_data, 1, match_arp, actions)

        first_path = paths_with_ports[0]
        first_path_switch = first_path[start_node]
        first_path_switch_out_port = first_path_switch[1]

        return first_path_switch_out_port

    # END OF PRIME HELPER FUNCTIONS ##

    # START OF EVENTS ##

    # Main func: acts when new packet hits controller #!
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        This func is how to route packets that are sent to the controller
        """
        msg = ev.msg  # OBJ that reps the packet_in data struct
        dp = msg.datapath  # OBJ that reps a datapath (switch)
        ofp = dp.ofproto  # OBJ that reps OF protocol
        ofp_parser = dp.ofproto_parser

        # In port
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        # Don't send packets for LLDP
        if eth.ethertype == LINK_LAYER_DISCOV_PROTOCOL:
            return None

        # Check if we're routing with IPv6
        is_ipv6 = False
        if pkt.get_protocol(ipv6.ipv6):
            is_ipv6 = True

        # Get handle on srt and end nodes + current node id
        start_node = eth.src
        end_node = eth.dst
        curr_node_id = dp.id

        # Add start_node to hosts tracker if not already there
        if start_node not in self.hosts:
            self.hosts[start_node] = (curr_node_id, in_port)

        # What port to send out of: default: flood all ports
        out_port = ofp.OFPP_FLOOD

        # If packet is an ARP then run multipath
        if arp_pkt:
            start_node_ip = arp_pkt.src_ip
            end_node_ip = arp_pkt.dst_ip

            # Filter by opcode
            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[start_node_ip] = start_node
                h1 = self.hosts[start_node]
                h2 = self.hosts[end_node]
                out_port = self.update_switch_path(
                    h1[0], h2[0], h1[1], h2[1], start_node_ip, end_node_ip,
                    ipv6=is_ipv6
                )
                self.update_switch_path(h2[0], h1[0], h2[1], h1[1], end_node_ip,
                                        start_node_ip, ipv6=is_ipv6
                                        )
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                # If the arp is a new request, setup links
                if end_node_ip in self.arp_table:
                    self.arp_table[start_node_ip] = start_node
                    end_node_mac = self.arp_table[end_node_ip]
                    h1 = self.hosts[start_node]
                    h2 = self.hosts[end_node_mac]
                    out_port = self.update_switch_path(
                        h1[0], h2[0], h1[1], h2[1], start_node_ip, end_node_ip,
                        ipv6=is_ipv6
                    )
                    self.update_switch_path(h2[0], h1[0], h2[1],
                                            h1[1], end_node_ip, start_node_ip,
                                            ipv6=is_ipv6)

        actions = [ofp_parser.OFPActionOutput(out_port)]

        # Build msg
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)

        # Send payload to node
        # print('# Packet Went Out.. Offending Switch: {}'.format(dp.id))
        # print('#'*40)
        dp.send_msg(out)

    # When a switch joins topo ##
    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser

        # If switch not currently being tracked, track it
        if switch.id not in self.switch_ids:
            self.switch_ids.append(switch.id)
            self.switch_by_id[switch.id] = switch

            # Request port/link descriptions
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

    # When a Switch leaves topo ##
    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        switch_id = ev.switch.dp.id
        if switch_id in self.switch_ids:
            self.switch_ids.remove(switch_id)
            del self.switch_links[switch_id]
            del self.switch_by_id[switch_id]

    # When requested, will return data about ports on switch ##
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        for body in ev.msg.body:
            self.bw_by_switch_id[switch.id][body.port_no] = body.curr_speed

    # Set default switch action
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        match = ofp_parser.OFPMatch()
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                              ofp.OFPCML_NO_BUFFER)]
        self.update_flow(dp, 0, match, actions)

    #
    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, event):

        s1 = event.link.src
        s2 = event.link.dst

        if s1.dpid not in self.switch_links:
            self.switch_links[s1.dpid] = {}
        if s2.dpid not in self.switch_links:
            self.switch_links[s2.dpid] = {}

        self.switch_links[s1.dpid][s2.dpid] = s1.port_no
        self.switch_links[s2.dpid][s1.dpid] = s2.port_no

        # print('Current Links:\n{}'.format(self.switch_links))

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, event):

        try:
            s1 = event.link.src
            s2 = event.link.dst
            del self.switch_links[s1.dpid][s2.dpid]
            del self.switch_links[s2.dpid][s1.dpid]
        except:
            print('Trouble deleting link {}:{}'.format(
                event.link.src, event.link.dst))

    # END OF EVENTS ##

    # START OF MULTIPATH ROUTING ##

    # Returns N num of paths in optimal order ##

    def calc_optimal_paths(self, start_node, end_node, no_of_paths=None):
        """
        A func that returns an ordered list of optimal paths between 2 nodes
        """
        # Get a handle on all paths
        all_paths = self._get_all_paths(start_node, end_node)

        # Use called defined limits or the default
        no_of_paths = no_of_paths or self.max_multipaths

        # Check if the num of total paths < the max path set
        if len(all_paths) < no_of_paths:
            no_of_paths = len(all_paths)

        # Order the paths based on weight
        sorted_paths = sorted(all_paths, key=lambda p: self._calc_path_cost(p))

        # Return only the max num of optiminal paths required
        return sorted_paths[0:no_of_paths]

    # WEIGHTS PATHS ##
    def _calc_path_cost(self, path):
        """
        Calculates the cost to travel from node1 to node2 based on BW of each node
        This is calculated based on OSPF
        """

        def calc_node_link_weight(s1, s2):
            '''
            Simple func to determine a weight between 2 nodes
            '''
            port_on_s1 = self.switch_links[s1][s2]
            port_on_s2 = self.switch_links[s2][s1]

            s1_link_speed = self.bw_by_switch_id[s1][port_on_s1]
            s2_link_speed = self.bw_by_switch_id[s2][port_on_s2]

            # Bottlenecked by lowest speed
            speed_limit = min(s1_link_speed, s2_link_speed)

            link_weight = DEFAULT_BW / speed_limit

            return link_weight

        path_weight = 0

        # Calc the costs of all node-links in the path
        for i in range(len(path) - 1):
            path_weight += calc_node_link_weight(path[i], path[i + 1])

        # return the weight of the path
        return path_weight

    # Returns all paths A to B ##
    def _get_all_paths(self, start_node, end_node):
        """
        Returns all paths from start_node to end_node as an array
        This is a DFS algorithm adapted to make use of ryu nodes

        start_node and end_node: should be the switch id
        """
        # Array to hold all paths
        paths = []

        # Check if the start node is same as end_node
        if start_node == end_node:
            path = [start_node]
            paths.append(path)
        else:
            # Use a stack to hold all possible routes as tuple (curr node, path)
            base_path = (start_node, [start_node])
            stack = [base_path]

            # Loop while there exists options to explore
            while stack:
                (curr_node_position, curr_path_to_node) = stack.pop()

                # TODO: Figure out why these need to be written here to exec.
                # Do not delete the following two lines.
                curr_node_position  # Both needed
                curr_path_to_node  # needed

                # Calculate options
                all_connected_nodes = self.switch_links[curr_node_position].keys(
                )
                remaining_node_options = set(
                    all_connected_nodes) - set(curr_path_to_node)

                # Loop over all avaible node options to traverse
                for next_node in remaining_node_options:

                    # Get handle on new path
                    new_path = curr_path_to_node + [next_node]
                    if next_node == end_node:
                        # reached final destination
                        paths.append(new_path)
                    else:
                        # Append new path to explore to stack
                        new_incomplete_path = (next_node, new_path)
                        stack.append(new_incomplete_path)

        # Return all possible paths
        # print('Av paths from {} to {} : {}'.format
        # (start_node, end_node, paths))
        return paths

    # END OF MULTIPATH ROUTING ##

    # START OF HELPER FUNCS ##

    def generate_random_id(self):
        """
        Returns a random group id
        """
        n = random.randint(0, 2**32)
        while n in self.group_ids:
            n = random.randint(0, 2**32)

        self.group_ids.append(n)
        return n

    def print_all(self, id, src, dst):
        """
        A function that prints all data about a connection
        """
        # Globals
        print('\n' + '#' * 40)
        print('Switch: {} -- Src: {} -- Dst: {}'.format(id, src, dst))
        print('#' * 40)
        print('switch_links', self.switch_links)      # [s1][s2] = port on s1
        print('hosts', self.hosts)             # [host] = (dp, port)

        print('arp_table', self.arp_table)

        # Trackers for grouping paths
        # [(switch, start_n, end_n)] = id
        print('multipath_group_ids', self.multipath_group_ids)
        print('group_ids', self.group_ids)
        print('\n' + '#' * 40)

    # END OF HELPER FUNCS ##
