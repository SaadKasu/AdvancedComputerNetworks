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
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types


class LearningRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningRouter, self).__init__(*args, **kwargs)
        self.arp_table = {}  # IP → (MAC, port)
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }
        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # Ignore LLDP

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self.handle_arp(datapath, in_port, eth, arp_pkt)
        elif ip_pkt:
            self.handle_ip(datapath, in_port, pkt, eth, ip_pkt)

    def handle_arp(self, datapath, in_port, eth, arp_pkt):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Learn sender's IP → MAC
        self.arp_table[arp_pkt.src_ip] = (arp_pkt.src_mac, in_port)

        # ARP request for router's IP?
        for port, own_ip in self.port_to_own_ip.items():
            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == own_ip:
                self.logger.info("Replying to ARP for %s", own_ip)
                reply_mac = self.port_to_own_mac[port]
                arp_reply = packet.Packet()
                arp_reply.add_protocol(ethernet.ethernet(
                    ethertype=ether_types.ETH_TYPE_ARP,
                    dst=eth.src,
                    src=reply_mac
                ))
                arp_reply.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=reply_mac,
                    src_ip=own_ip,
                    dst_mac=arp_pkt.src_mac,
                    dst_ip=arp_pkt.src_ip
                ))
                arp_reply.serialize()

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=arp_reply.data,
                    buffer_id=ofproto.OFP_NO_BUFFER)
                datapath.send_msg(out)
                return

    def handle_ip(self, datapath, in_port, pkt, eth, ip_pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        self.arp_table[src_ip] = (eth.src, in_port)  # Learn sender

        # Check if router knows where to send dst_ip
        dst_entry = self.arp_table.get(dst_ip)
        if not dst_entry:
            self.logger.info("Unknown MAC for %s — sending ARP request", dst_ip)
            self.send_arp_request(datapath, dst_ip)
            return

        dst_mac, out_port = dst_entry

        # Find which port to send from (router's port in that subnet)
        send_port = None
        for port, subnet_ip in self.port_to_own_ip.items():
            if dst_ip.startswith(subnet_ip.rsplit('.', 1)[0]):
                send_port = port
                break
        if send_port is None:
            self.logger.warning("No route for IP %s", dst_ip)
            return

        # Rebuild Ethernet frame with correct MACs
        new_eth = ethernet.ethernet(dst=dst_mac,
                                    src=self.port_to_own_mac[send_port],
                                    ethertype=eth.ethertype)

        new_pkt = packet.Packet()
        new_pkt.add_protocol(new_eth)
        for p in pkt.protocols[1:]:  # Skip original Ethernet header
            new_pkt.add_protocol(p)
        new_pkt.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=new_pkt.data,
            buffer_id=ofproto.OFP_NO_BUFFER)
        datapath.send_msg(out)

    def send_arp_request(self, datapath, target_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Figure out which port to send from
        for port, subnet_ip in self.port_to_own_ip.items():
            if target_ip.startswith(subnet_ip.rsplit('.', 1)[0]):
                src_mac = self.port_to_own_mac[port]
                src_ip = subnet_ip

                arp_req = arp.arp(opcode=arp.ARP_REQUEST,
                                  src_mac=src_mac,
                                  src_ip=src_ip,
                                  dst_mac='00:00:00:00:00:00',
                                  dst_ip=target_ip)
                eth = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',
                                        src=src_mac,
                                        ethertype=ether_types.ETH_TYPE_ARP)
                pkt = packet.Packet()
                pkt.add_protocol(eth)
                pkt.add_protocol(arp_req)
                pkt.serialize()

                actions = [parser.OFPActionOutput(port)]
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=pkt.data,
                    buffer_id=ofproto.OFP_NO_BUFFER)
                datapath.send_msg(out)
                return
