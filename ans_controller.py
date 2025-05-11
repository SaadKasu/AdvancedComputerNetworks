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
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.mac_to_port = {}
        self.routing_table = {}  # prefix -> port
        self.arp_table = {}  # IP -> MAC
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
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s %s %s", dpid, src, dst, in_port, eth, datapath)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, in_port, pkt)
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            self.handle_ip(datapath, in_port, pkt)

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


    def handle_ip(self, datapath, in_port, pkt):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        # Learn the source IP and the input port
        # This allows the router to learn how to reach the source of the packet
        if src_ip not in self.routing_table:
            self.routing_table[src_ip] = in_port
            self.logger.info(f"Learning route: {src_ip} -> Port {in_port}")

        # If the destination IP is one of the router's own IPs, process the packet (e.g., for ICMP reply)
        if dst_ip in self.port_to_own_ip.values():
            # Handle incoming packet that is destined for the router itself
            # If it's an ICMP Echo Request, respond with Echo Reply
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt and icmp_pkt.type == 8:  # ICMP Echo Request
                self.send_icmp_reply(datapath, pkt, in_port)
            return
        
        # Look up next-hop MAC address in the ARP table (we expect it to be learned)
        if dst_ip not in self.arp_table:
            self.logger.info(f"Destination IP {dst_ip} not in ARP table")
            return  # ARP not resolved, can't forward the packet

        # Get the next-hop MAC from ARP table
        next_hop_mac = self.arp_table[dst_ip]

        # Find which port the packet should be forwarded out of
        # Look for a port that matches the destination IP based on the routing table (prefix matching)
        out_port = self.routing_table.get(dst_ip)  # Simple direct lookup for now

        if not out_port:
            self.logger.info(f"No route for destination IP {dst_ip}")
            return  # No route found

        # Prepare the Ethernet frame for forwarding
        eth_pkt.src = self.port_to_own_mac[in_port]  # Source MAC is based on incoming port
        eth_pkt.dst = next_hop_mac  # Destination MAC from ARP table
        pkt.serialize()

        # Add flow entry to forward future packets of the same type directly
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        match = datapath.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)
        self.add_flow(datapath, 10, match, actions)

        # Forward the packet
        datapath.send_packet_out(
            in_port=in_port,
            actions=actions,
            data=pkt.data
        )

    def handle_arp(self, datapath, in_port, pkt):
        arp_pkt = pkt.get_protocol(arp.arp)
        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac
        dst_ip = arp_pkt.dst_ip

        # Learn source IP and MAC
        self.arp_table[src_ip] = src_mac

        # Respond only if the ARP request is for one of the router's IPs
        if arp_pkt.opcode == arp.ARP_REQUEST:
            if dst_ip in port_to_own_ip.values():
                # Find the port whose IP matches
                for port, ip in port_to_own_ip.items():
                    if ip == dst_ip:
                        src_mac = port_to_own_mac[port]
                        break
                else:
                    return  # IP not found in mapping (shouldn't happen)

                # Build ARP reply
                ether_reply = ethernet.ethernet(
                    ethertype=ether_types.ETH_TYPE_ARP,
                    dst=arp_pkt.src_mac,
                    src=src_mac
                )
                arp_reply = arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=src_mac,
                    src_ip=dst_ip,
                    dst_mac=arp_pkt.src_mac,
                    dst_ip=arp_pkt.src_ip
                )

                reply_pkt = packet.Packet()
                reply_pkt.add_protocol(ether_reply)
                reply_pkt.add_protocol(arp_reply)
                reply_pkt.serialize()

                actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=datapath.ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=reply_pkt.data
                )
                datapath.send_msg(out)

    def send_icmp_reply(self, datapath, pkt, in_port):
        # Create ICMP Echo Reply
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        # Swap source and destination IP addresses
        reply_ip = ipv4.ipv4(
            src=ip_pkt.dst,
            dst=ip_pkt.src,
            proto=inet.IPPROTO_ICMP
        )

        # Swap ICMP type to Echo Reply
        reply_icmp = icmp.icmp(
            type_=icmp.ICMP_ECHO_REPLY,
            code=0,
            csum=0,
            data=icmp_pkt.data
        )

        # Create the Ethernet frame for the reply
        ether_pkt = ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_IP,
            src=self.port_to_own_mac[in_port],  # Router's source MAC
            dst=pkt.get_protocol(ethernet.ethernet).src  # Source MAC from the incoming packet
        )

        # Construct the full packet
        reply_pkt = packet.Packet()
        reply_pkt.add_protocol(ether_pkt)
        reply_pkt.add_protocol(reply_ip)
        reply_pkt.add_protocol(reply_icmp)
        reply_pkt.serialize()

        # Send the reply
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=reply_pkt.data
        )
        datapath.send_msg(out)
