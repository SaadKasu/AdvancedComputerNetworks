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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.mac_to_port = {}
        # Router port MACs assumed by the controller
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }
        # Router port (gateways) IP addresses assumed by the controller
        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }
        self.arp_table = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
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

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)#This decorator tells Ryu when the decorated function should be called. The first argument of the decorator indicates which type of event this function should be called for. The second argument indicates the state of the switch. You probably want to ignore packet_in messages before the negotiation between Ryu and the switch is finished.
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s %s %s", dpid, src, dst, in_port, eth, datapath)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        
        if dpid==3:
            # Handle ARP packets
            if eth.ethertype == ether_types.ETH_TYPE_ARP and arp_pkt:
                self.handle_arp(datapath, pkt, arp_pkt, in_port)
                return
            # Handle IP packets
            elif eth.ethertype == ether_types.ETH_TYPE_IP and ip_pkt:
                self.handle_ip(datapath, pkt, ip_pkt, in_port)
                return
            return

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, ofproto.OFP_DEFAULT_PRIORITY, datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src), actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, ofproto.OFP_DEFAULT_PRIORITY, datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src), actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    def handle_arp(self, datapath, pkt, arp_pkt, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dst_ip = arp_pkt.dst_ip
        src_ip = arp_pkt.src_ip
        self.logger.info("Handling an ARP Request SRC IP : %s DST IP : %s In_Port : %s SRC Mac : %s DST Mac : %s",src_ip,dst_ip, in_port, arp_pkt.dst_mac, arp_pkt.dst_mac)
        # If the router owns the IP (destination IP is one of the router's IPs), reply
        
        if dst_ip == self.port_to_own_ip[in_port]:
            self.logger.info("Inside The ARP if condition")
            # Send ARP reply
            arp_reply = arp.arp(opcode=arp.ARP_REPLY, src_mac=self.port_to_own_mac[in_port], src_ip=self.port_to_own_ip[in_port], dst_mac=arp_pkt.src_mac, dst_ip=src_ip)
            eth = ethernet.ethernet(dst=arp_pkt.src_mac, src=self.port_to_own_mac[in_port], ethertype=ether_types.ETH_TYPE_ARP)
            reply_pkt = packet.Packet()
            reply_pkt.add_protocol(eth)
            reply_pkt.add_protocol(arp_reply)
            reply_pkt.serialize()

            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_CONTROLLER,
                                      actions=actions, data=reply_pkt.data,
                                      buffer_id=ofproto.OFP_NO_BUFFER)
            datapath.send_msg(out)

        else:
            self.logger.info("Inside The ARP else condition") 
            arp_reply = arp.arp(opcode=arp.ARP_REPLY, src_mac=arp_pkt.src_mac, src_ip=src_ip, dst_mac=arp_pkt.dst_mac, dst_ip=dst_ip)
            eth = ethernet.ethernet(dst=arp_pkt.dst_mac, src=arp_pkt.src_mac, ethertype=ether_types.ETH_TYPE_ARP)
            reply_pkt = packet.Packet()
            reply_pkt.add_protocol(eth)
            reply_pkt.add_protocol(arp_reply)
            reply_pkt.serialize()

            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_CONTROLLER,
                                      actions=actions, data=reply_pkt.data,
                                      buffer_id=ofproto.OFP_NO_BUFFER)
            datapath.send_msg(out)    

    def handle_ip(self, datapath, pkt, ip_pkt, in_port):
        dst_ip = ip_pkt.dst
        src_ip = ip_pkt.src
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Learn the source MAC and IP mapping
        eth = pkt.get_protocol(ethernet.ethernet)
        self.logger.info("Inside Handel IP eth_src : %s in_port: %s src_ip : %s", eth.src, in_port, src_ip)
        self.arp_table[src_ip] = (eth.src, in_port)

        # Check if the destination IP is known
        if dst_ip in self.arp_table:
            # Get the destination MAC and output port from the ARP table
            dst_mac, out_port = self.arp_table[dst_ip]
            src_mac = self.port_to_own_mac[out_port]  # Get router MAC for this port

            # Rewrite Ethernet frame with destination MAC and router's source MAC
            eth.dst = dst_mac
            eth.src = src_mac
            pkt.serialize()

            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath, in_port=in_port, actions=actions,
                                      data=pkt.data, buffer_id=ofproto.OFP_NO_BUFFER)
            datapath.send_msg(out)

            # Install flow to avoid future flooding of the same packet
            match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_dst=dst_ip, ipv4_src=src_ip)
            self.add_flow(datapath, 1, match, actions)
        else:
            # If destination IP is unknown, flood the IP packet
            self.logger.info("Flooding IP packet for unknown destination Inside Handle IP: %s", dst_ip)
            flood_ports = [port for port in self.port_to_own_mac if port != in_port]
            actions = [parser.OFPActionOutput(port) for port in flood_ports]
            out = parser.OFPPacketOut(datapath=datapath, in_port=in_port, actions=actions,
                                      data=pkt.data, buffer_id=ofproto.OFP_NO_BUFFER)
            datapath.send_msg(out)
