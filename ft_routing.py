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
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

import topo


class FTRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)
        
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
        self.edge_dpid = [48,49,50,51,52,53,54,55]
        self.aggr_dpid = [32,33,34,35,36,37,38,39]
        self.core_dpid = [16,17,18,19]
        self.dpid_prefix = {}
        self.dpid_suffix = {}
        self.dpid_ip = {}

    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):

        # Switches and links in the network
        self.switches = get_switch(self, None)
        self.links = get_link(self, None)

        for switch in self.switches :
            self.dpid_neighbours.setdefault(switch.dp.id, {})
            self.switch_datapath[switch.dp.id] = switch.dp

            switch_type = ""
            pod_num = 0
            subnet_num = 0
            start_num = 1
            ip = ""

            self.dpid_prefix.setdefault(switch.dp.id, {})
            self.dpid_suffix.setdefault(switch.dp.id, {})
            
            if switch.dp.id in self.edge_dpid :
                switch_type = "edge"
                pod_num = int((switch.dp.id - self.edge_dpid[0])/2)
                subnet_num = int((switch.dp.id - self.edge_dpid[0])%2)
                start_num = 1
            elif switch.dp.id in self.aggr_dpid :
                switch_type = "aggr"
                pod_num = int((switch.dp.id - self.aggr_dpid[0])/2)
                subnet_num = int((switch.dp.id - self.aggr_dpid[0])%2) + 2
                start_num = 1
            else :
                switch_type = "core"
                pod_num = 4
                subnet_num = int((switch.dp.id - self.core_dpid[0])/2) + 1
                start_num = int((switch.dp.id - self.core_dpid[0])%2) + 1

            ip = "10."+str(pod_num)+"."+str(subnet_num)+"."+str(start_num)

            self.dpid_ip[switch.dp.id] = ip   

        for link in self.links:
            #print("\n Link - ", link)
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
            print("\n The neighbours of switch - ", switchId, " Ip of the switch - ", self.dpid_ip[switchId], " is : ")
            for key in neighbours :
                print("\n Neighbour - ",key, " At Port - ", neighbours[key])
                
                

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install entry-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 10, match, actions)


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
        self.arp_table[src] = (eth.src, in_port)

        #print(" IP data path - ", self.ip_datapath)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, pkt, in_port, eth)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            self.handle_ip(dpid, pkt.get_protocol(ipv4.ipv4), in_port, msg, eth)
        

    def handle_ip(self,dpid, pkt, in_port, msg, eth_pkt):

        src = pkt.src
        dst = pkt.dst
        print("\nThe Host - ", src, " is at Switch - ", dpid, " at port - ", in_port)
        print("\nHandling an IP Request SRC IP : %s DST IP : %s In_Port : %s",src,dst, in_port)

        port_type = ""
        switch_type = ""
        
        if dpid in self.edge_dpid :
            switch_type = "edge"
        elif dpid in self.aggr_dpid :
            switch_type = "aggr"
        else :
            switch_type = "core"
        """
        if switch_type != "core" and (in_port == 1 or in_port == 2):
            port_type = "up"
        else :
            port_type = "down"
        """

        if self.prefix_match(dst, dpid) :
            print("\n Prefix Match Successful, Dp id IP - ", self.dpid_ip[dpid], " Dst - ",dst, " Src - ", src)

            port_no = self.suffix_match(dst, dpid)

            if port_no == 0:
                print("Could Not Find The Correct Output Port")
                return
            
        else :
            print("\n Prefix Match Unsuccessful, Dp id IP - ", self.dpid_ip[dpid], " Dst - ",dst)
            if switch_type == "core" :
                pod_num = int(dst[3:4])
                port_no = pod_num + 1
            else :
                port_no = int(dpid%2) + 1
        print("\n Switch Type - ",switch_type, " Out Port - ", port_no, )
        self.add_flow (self.switch_datapath[dpid],
        10 , self.switch_datapath[dpid].ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst),
        [self.switch_datapath[dpid].ofproto_parser.OFPActionOutput(port_no)])
        self.forwardPacket(dpid, msg, eth_pkt, src, dst, pkt,port_no)
            
            

    def forwardPacket(self, dpid, msg, eth_pkt, src, dst, pkt, port_no) :

        datapath = self.switch_datapath[dpid]
        eth_pkt = ethernet.ethernet(dst=self.arp_table[dst][0], src=self.arp_table[src][0], ethertype=eth_pkt.ethertype)
        ipv4_pkt = ipv4.ipv4(dst=dst, src=src, proto=pkt.proto)
        pkt = packet.Packet()            
        pkt.add_protocol(eth_pkt)
        pkt.add_protocol(ipv4_pkt)  
        pkt.serialize()
        ofproto = datapath.ofproto
        actions = [datapath.ofproto_parser.OFPActionOutput(port_no)]
        out = datapath.ofproto_parser.OFPPacketOut(
        datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
        actions=actions, data=msg.data)
        datapath.send_msg(out)
            

    def prefix_match(self, dst, dpid) :

        dp_ip = self.dpid_ip[dpid]
        return dp_ip[0:4] == dst[0:4]

    def suffix_match(self, dst, dpid) :
        port_list = []
        neighbours = self.dpid_neighbours [dpid]
        for neigh_dpid in neighbours :
            neighbour_ip = self.dpid_ip[neigh_dpid]
            if neighbour_ip[5:7] == dst[5:7]:
                port_list.append(neighbours[neigh_dpid])

        if len(port_list) > 1 :
            return port_list[dpid%2]
        elif len(port_list) > 0 : 
            return port_list[0]
        elif dst in self.ip_datapath :
            return self.ip_datapath[dst][1]
        return 0
        

    def handle_arp(self, datapath, pkt, in_port, eth):

        arp_pkt = pkt.get_protocol(arp.arp) 
                

        if arp_pkt.opcode == arp.ARP_REQUEST : 
            self.handle_arp_request(datapath, in_port, eth, arp_pkt)
        elif arp_pkt.opcode == arp.ARP_REPLY:
            self.handle_arp_reply_from_reply(datapath, in_port, eth, arp_pkt)


    def handle_arp_request(self, datapath, in_port, eth, arp_pkt):

        dst_ip = arp_pkt.dst_ip

        if dst_ip in self.arp_table:
        # We know the MAC: send ARP reply directly
            self.handle_arp_reply_from_request(datapath, in_port, eth, arp_pkt)
        else:
            # Unknown: flood request to all edge switches
            self.flood_arp(datapath, eth, arp_pkt)

    def handle_arp_reply_from_request(self, datapath, in_port, eth, arp_pkt):

        self.logger.info("Handling an ARP Reply SRC IP : %s DST IP : %s In_Port : %s SRC Mac : %s DST Mac : %s",arp_pkt.src_ip,arp_pkt.dst_ip, in_port, eth.src, eth.dst)

        dst_mac = self.arp_table[arp_pkt.src_ip][0]
        src_mac = self.arp_table[arp_pkt.dst_ip][0]

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

    def handle_arp_reply_from_reply(self, datapath, in_port, eth, arp_pkt):

        self.logger.info("Handling an ARP Reply SRC IP : %s DST IP : %s In_Port : %s SRC Mac : %s DST Mac : %s",arp_pkt.src_ip,arp_pkt.dst_ip, in_port, eth.src, eth.dst)

        src_mac = self.arp_table[arp_pkt.src_ip][0]
        dst_mac = self.arp_table[arp_pkt.dst_ip][0]

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=dst_mac,
            src=src_mac))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            dst_ip=arp_pkt.dst_ip,
            dst_mac=dst_mac,
            src_ip=arp_pkt.src_ip))

        pkt.serialize()
        datapath = self.switch_datapath[self.ip_datapath[arp_pkt.dst_ip][0]]
        in_port = self.ip_datapath[arp_pkt.dst_ip][1]

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
            #print("\nValues - ",values, " For DPID - ", key)
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
