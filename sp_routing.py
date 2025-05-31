"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from collections import defaultdict

import topo

class SPRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        
        # Initialize the topology with #ports=4
        self.topo_net = topo.Fattree(4)
        self.switches = []
        self.mac_switch_port_map = {}
        self.datapath_list = {} #Save datapath contents of a switch
        self.switch_count = 0

        self.adjacency=defaultdict(lambda:defaultdict(lambda:None))
        self.switch_dpid_list = []
        self.global_mac_table = {}
        self.switch_mac_table = []
        self.network_topology = {}
        self.found_paths = [[]]
        self.controller_mac ="0A:00:27:00:00:43"
        self.controller_ip = "127.0.0.1"

    def dijkstra(src, dst, first_port, final_port):

        distance = {}
        previous = {}
        for dpid in self.switch_dpid_list:
            distance[dpid] = float('Inf')
            previous[dpid] = None
        distance[src] = 0
        Q = set(self.switch_dpid_list)

        while len(Q) > 0:
            u = minimum_distance(distance, Q)
            Q.remove(u)

            for p in self.switch_dpid_list:
                if self.adjacency[u][p] != None:
                    if distance[p] > distance[u] + self.network_topology[u][p]:
                        distance[p] = distance[u] + self.network_topology[u][p]
                        previous[p] = u
        r = []
        p = dst
        r.append(p)
        q = previous[p]
        while q is not None:
            if q == src:
                r.append(q)
                break
            p = q
            r.append(p)
            q = previous[p]
        r.reverse()
        if src == dst:
            path = [src]
        else:
            path = r



        # Adding the ports
        r = []
        in_port = first_port
        for s1, s2 in zip(path[:-1], path[1:]):
            out_port = self.adjacency[s1][s2]
            r.append((s1, in_port, out_port))
            in_port = self.adjacency[s2][s1]
        r.append((dst, in_port, final_port))
        # print("The result is: ", r)
        return r
        
    def minimum_distance(distance, Q):
        min = float('Inf')
        node = 0
        for v in Q:
            if distance[v] < min:
                min = distance[v]
                node = v
        return node

    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):

        # Switches and links in the network
        self.switches = get_switch(self, None)
        links = get_link(self, None)

         # getting dpid of each switch
        self.switch_dpid_list = [switch.dp.id for switch in self.switches]
        #  self.datapath_list = [switch.dp for switch in switch_list]  # getting the datapath of each switch
        for switch in self.switches:
            self.datapath_list[switch.dp.id] = switch.dp

        mylinks = [(link.src.dpid, link.dst.dpid, link.src.port_no, link.dst.port_no) for link in links]
        for s1, s2, port1, port2 in mylinks:
            # If the direction of a link is: From source dpid to destination dpid ( let's
            # say from switch number 1 to switch number 2), then the egress port would be source port of this link
            # object and vice versa
            self.adjacency[s1][s2] = port1
            self.adjacency[s2][s1] = port2  # This is the vice versa :D

        for dpid_src, dpid_dst, src_port, dst_port in links:
            self.network_topology[dpid_src][dpid_dst] = 1

        self.switch_mac_table = [{} for x in range(self.switch_count + 1)]


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
    
        # Set initial values for all links to this switch to infinite
        self.network_topology[datapath.id] = {}
        self.switch_count += 1

        
        for id in self.network_topology:
            self.network_topology[id][datapath.id] = float('inf')
            self.network_topology[datapath.id][id] = float('inf')

        # Set the value of the link to the current switch to 0
        self.network_topology[datapath.id][datapath.id] = 0

        # Install entry-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)  # the data from the packet will be exported for further changes
        in_port = None
        out_port = None
        for f in msg.match.fields:
            if f.header == ofproto_v1_3.OXM_OF_IN_PORT:
                in_port = f.value

        eth = pkt.get_protocol(ethernet.ethernet)
        src_mac = eth.src
        dst_mac = eth.dst
        dpid = datapath.id

        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore lldp packet
            return
        #  This mac "01:80:c2:00:00:0e" is my controller mac address which is automatically added in the match field of another table-miss flow in each switch. It is added by the option
        #  "--observe-links" in the beginning of ruunning the controller. This option is mandatory to find the topology using RYU api.
        if eth.ethertype == ether_types.ETH_TYPE_ARP: #and dst_mac != "0A:00:27:00:00:17"
            self.handle_arp(datapath, pkt, src_mac, dst_mac, in_port, msg)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst

        if src_mac not in self.global_mac_table.keys():
            self.global_mac_table[src_mac] = (dpid, in_port)

        if dst_mac in self.global_mac_table.keys():
            p = dijkstra(self.global_mac_table[src_mac][0], self.global_mac_table[dst_mac][0], self.global_mac_table[src_mac][1],
                         self.global_mac_table[dst_mac][1])

            if p not in self.found_paths:
                self.found_paths.append(p)
                self.install_path(p, ev, src_mac, dst_mac)
                # this will be the output port for this switch to redirect the packets to the desired destination
                out_port = p[0][2]
            else:
                out_port = p[0][2]
                return
        else:
            # when the dst isn't found then it shall be flooded to all output ports
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            # Data is set due to no buffering
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions,
                                  data=data)
        datapath.send_msg(out)
        # TODO: handle new packets at the controller


    def handle_arp(self, datapath, pkt, src, dst, in_port, msg):

        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        data = None
        arp_pkt = pkt.get_protocol(arp.arp)
        arp_spa = arp_pkt.src_ip  # getting the src ip address of the arp request
        arp_tpa = arp_pkt.dst_ip

        if arp_pkt.opcode == arp.ARP_REQUEST:  # check if it's an arp request
            if arp_tpa == self.controller_ip:  # If a host sends an arp req for the controller ip, then this packet is for the controller
                arp_reply = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                                    src_mac=self.controller_mac, src_ip=self.controller_ip,
                                    dst_mac=src, dst_ip=arp_spa)
                eth_header = ethernet.ethernet(
                    dst=src,
                    src=self.controller_mac,
                    ethertype=ether.ETH_TYPE_ARP)
                arp_reply_pkt = packet.Packet()
                arp_reply_pkt.add_protocol(eth_header)
                arp_reply_pkt.add_protocol(arp_reply)
                arp_reply_pkt.serialize()
                arp_action = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=ofp.OFP_NO_BUFFER,
                                          in_port=ofp.OFPP_ANY,
                                          actions=arp_action,
                                          data=arp_reply_pkt.data)
                datapath.send_msg(out)
                return
            #self.logger.info("\n Data path - %s",datapath,"\n Datapath id - %s", datapath.id, "\n Map - %s", self.switch_mac_table)
            #self.logger.info("\n Map with Key - %s",self.switch_mac_table[datapath.id], "\n Keys - %s",self.switch_mac_table[datapath.id].keys())
            if src not in self.switch_mac_table[datapath.id].keys():
                self.switch_mac_table[datapath.id][src] = (in_port, arp_tpa)  # Updating mac table of this 
                if msg.buffer_id == ofp.OFP_NO_BUFFER:
                    data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions,
                                          data=data)
                datapath.send_msg(out)
                return
            if src in self.switch_mac_table[datapath.id].keys():
                if arp_tpa in self.switch_mac_table[datapath.id][src]:
                    return

                else:
                    self.switch_mac_table[datapath.id][src] = (in_port, arp_tpa)
                    if msg.buffer_id == ofp.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                                              actions=actions,
                                              data=data)
                    datapath.send_msg(out)
                    return

        if arp_pkt.opcode == arp.ARP_REPLY:  # check if it's an arp reply
            if dst in self.switch_mac_table[datapath.id].keys():
                parser = datapath.ofproto_parser
                ofp = datapath.ofproto
                actions = [parser.OFPActionOutput(self.switch_mac_table[datapath.id][dst][0])]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                          in_port=in_port, actions=actions, data=msg.data)
                datapath.send_msg(out)


    def install_path(self, p, ev, src_mac, dst_mac):
        shortest_path_route = ""
        for z in p:
            shortest_path_route += str(z[0]) + "-"

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for sw, in_port, out_port in p:
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            datapath = self.datapath_list[int(sw)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, idle_timeout=10, hard_timeout=0, priority=1, instructions=inst)
            datapath.send_msg(mod)
