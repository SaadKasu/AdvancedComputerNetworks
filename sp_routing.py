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
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp, ether_types
import heapq
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

import topo

class SPRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        
        # Initialize the topology with #ports=4
        self.topo_net = topo.Fattree(4)
        self.dpid_neighbours = {}
        self.distance_between_switches = {}
        self.path_between_switches = {}
        self.ip_datapath = {}
        self.switch_datapath = {}
        self.switches = []
        self.links = []
        self.arp_table = {}
        self.switch_without_hosts = {}

    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):

        # Switches and links in the network
        self.switches = get_switch(self, None)
        self.links = get_link(self, None)

        for switch in self.switches :
            self.dpid_neighbours.setdefault(switch.dp.id, {})
            self.switch_datapath[switch.dp.id] = switch.dp

        for link in self.links:
            src = link.src
            dst = link.dst

            if dst.dpid not in self.switch_without_hosts :
                self.switch_without_hosts[dst.dpid] = set()
            if src.dpid not in self.switch_without_hosts :
                self.switch_without_hosts[src.dpid] = set()

            self.switch_without_hosts[dst.dpid].add(dst.port_no)
            self.switch_without_hosts[src.dpid].add(src.port_no)
    
            if src.dpid not in self.dpid_neighbours[dst.dpid]:
                self.dpid_neighbours[dst.dpid][src.dpid] = dst.port_no
            
            if dst.dpid not in self.dpid_neighbours[src.dpid]:
                self.dpid_neighbours[src.dpid][dst.dpid] = src.port_no

        for switchId in self.dpid_neighbours :
            neighbours = self.dpid_neighbours [switchId]
            print("\n The neighbours of switch - ", switchId, " is : ")
            for key in neighbours :
                print("\n Neighbour - ",key, " At Port - ", neighbours[key])
                """
        for switch in self.switches:
            self.path_between_switches[switch.dp.id] = {}
            self.distance_between_switches[switch.dp.id] = {}

            self.dijkstra(switch.dp.id, switches)

        for switch_src in switches :
            for switch_dst in switches :    
                print("Path between - ",switch_src.dp.id, " and Destination - ",switch_dst.dp.id, " is - ",self.path_between_switches[switch_src.dp.id][switch_dst.dp.id])
        """

    def dijkstra(self, source, destination):
        dist = {}
        prev = {}
        for switch in self.switches :
            dist[switch.dp.id] = float('inf')
            prev[switch.dp.id] = (None,None)
        dist[source] = 0
        queue = [(0,source)]
        visitedNodes = []

        poped_node = heapq.heappop(queue)
        curr_dist = poped_node[0]
        curr_switch = poped_node[1]
        while curr_switch != destination: 
            visitedNodes.append(curr_switch)
            #self.distance_between_switches[source][curr_switch] = dist[curr_switch]
            for neighbour in self.dpid_neighbours[curr_switch]:
                nextDist = dist[curr_switch] + 1
                if nextDist < dist[neighbour] and neighbour not in visitedNodes :
                    dist[neighbour] = nextDist
                    prev[neighbour] = (curr_switch, self.dpid_neighbours[curr_switch][neighbour])
                    heapq.heappush(queue, (nextDist, neighbour))
            poped_node = heapq.heappop(queue)
            curr_dist = poped_node[0]
            curr_switch = poped_node[1]

        path = []
        previousNode = prev[destination]
        #self.path_between_switches[source].setdefault(destination,[])
        while previousNode[0] is not None :
            path.insert(0, previousNode)
            destination = prev[destination][0]
            if destination is not None : 
                previousNode = prev[destination]

        return path

        #self.path_between_switches[source][switch.dp.id] = path
        
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        in_port = msg.match['in_port']
        src = ""
        dst = ""
        prot_pkt = ""

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            prot_pkt = pkt.get_protocol(arp.arp)
            src = prot_pkt.src_ip  # getting the src ip address of the arp request
            dst = prot_pkt.dst_ip

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            prot_pkt = pkt.get_protocol(ipv4.ipv4)
            src = prot_pkt.src
            dst = prot_pkt.dst
            
        self.ip_datapath[src]= (dpid, in_port)
        self.arp_table[src] = eth.src

        #print(" IP data path - ", self.ip_datapath)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, pkt, in_port, eth)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            self.handle_ip(dpid, pkt.get_protocol(ipv4.ipv4), in_port, msg)

    def handle_ip(self,dpid, pkt, in_port, msg):

        src = pkt.src
        dst = pkt.dst

        
        self.logger.info("Handling an IP Request SRC IP : %s DST IP : %s In_Port : %s",src,dst, in_port)
    
        if dst not in self.ip_datapath :
            """
            datapath = self.switch_datapath[dpid]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            # Data is set due to no buffering
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions,data=data)
            datapath.send_msg(out)
            """
            return


        else : 
            print(" Has out put port")
            dst_sw = self.ip_datapath[dst][0]
            dst_port = self.ip_datapath[dst][1]
            src_sw = dpid
            src_port = in_port

            path = self.dijkstra(src_sw, dst_sw)
            path.append(dst_sw, dst_port)

            print("Path between SRC - ",src_sw, " DST - ", dst_sw, " is - ", path)
            
            for sw_dpid, port in path :
                datapath = self.switch_datapath[sw_dpid]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst)
                actions = [parser.OFPActionOutput(port)]
                self.add_flow(datapath, 10, match, actions)

"""
            datapath = self.switch_datapath[dst_sw]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst)
            actions = [parser.OFPActionOutput(dst_port)]
            self.add_flow(datapath, 10, match, actions)
            """

        

    def handle_arp(self, datapath, pkt, in_port, eth):

        arp_pkt = pkt.get_protocol(arp.arp) 
                

        if arp_pkt.opcode == arp.ARP_REQUEST : 
            self.handle_arp_request(datapath, in_port, eth, arp_pkt)
        elif arp_pkt.opcode == arp.ARP_REPLY:
            self.handle_arp_reply(datapath, in_port, eth, arp_pkt)


    def handle_arp_request(self, datapath, in_port, eth, arp_pkt):

        dst_ip = arp_pkt.dst_ip

        if dst_ip in self.arp_table:
        # We know the MAC: send ARP reply directly
            self.handle_arp_reply(datapath, in_port, eth, arp_pkt)
        else:
            # Unknown: flood request to all edge switches
            self.flood_arp(datapath, eth, arp_pkt)

    def handle_arp_reply(self, datapath, in_port, eth, arp_pkt):

        self.logger.info("Handling an ARP Reply SRC IP : %s DST IP : %s In_Port : %s SRC Mac : %s DST Mac : %s",arp_pkt.src_ip,arp_pkt.dst_ip, in_port, eth.src, eth.dst)

        dst_mac = self.arp_table[arp_pkt.src_ip]
        src_mac = self.arp_table[arp_pkt.dst_ip]

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=dst_mac,
            src=src_mac))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            src_ip=arp_pkt.dst_ip,
            dst_mac=dst_mac,
            dst_ip=arp_pkt.src_ip))

        pkt.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            actions=actions,
            data=pkt.data)
        datapath.send_msg(out)


    def flood_arp(self, datapath, eth, arp_pkt):

        self.logger.info("Handling an flood ARP SRC IP : %s DST IP : %s SRC Mac : %s DST Mac : %s",arp_pkt.src_ip,arp_pkt.dst_ip, eth.src, eth.dst)

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst='ff:ff:ff:ff:ff:ff',
            src=eth.src))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=eth.src,
            src_ip=arp_pkt.src_ip,
            dst_mac='00:00:00:00:00:00',
            dst_ip=arp_pkt.dst_ip))

        pkt.serialize()

        for key in self.switch_without_hosts :
            values = self.switch_without_hosts[key]
            print("\nValues - ",values, " For DPID - ", key)
            if len(values) < 4 : 
                dp = self.switch_datapath[key]
                for port in range(1, 5):  # adjust based on your topology
                    if port not in values : 
                        #print("\nHost on port - ", port, " Switch id - ", key)
                        actions = [dp.ofproto_parser.OFPActionOutput(port)]
                        out = dp.ofproto_parser.OFPPacketOut(
                            datapath=dp,
                            in_port=dp.ofproto.OFPP_CONTROLLER,
                            buffer_id=dp.ofproto.OFP_NO_BUFFER,
                            actions=actions,
                            data=pkt.data)
                        dp.send_msg(out)
