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
        self.interface_ips = {}     # IP → (MAC, port)
        self.arp_table = {}         # IP → (MAC, port)
        self.packet_buffer = {}     # IP → list of (datapath, in_port, packet)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER,
                                          datapath.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_ARP and arp_pkt:
            self.handle_arp(datapath, pkt, arp_pkt, in_port)
        elif eth.ethertype == ether_types.ETH_TYPE_IP and ip_pkt:
            self.handle_ip(datapath, pkt, ip_pkt, eth, in_port)

    def handle_arp(self, datapath, pkt, arp_pkt, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac
        dst_ip = arp_pkt.dst_ip

        # Learn sender's info
        self.arp_table[src_ip] = (src_mac, in_port)

        # If the router owns the target IP, reply
        if dst_ip in self.interface_ips:
            dst_mac, out_port = self.interface_ips[dst_ip]

            eth_reply = ethernet.ethernet(dst=src_mac, src=dst_mac,
                                          ethertype=ether_types.ETH_TYPE_ARP)
            arp_reply = arp.arp(opcode=arp.ARP_REPLY,
                                src_mac=dst_mac, src_ip=dst_ip,
                                dst_mac=src_mac, dst_ip=src_ip)

            reply_pkt = packet.Packet()
            reply_pkt.add_protocol(eth_reply)
            reply_pkt.add_protocol(arp_reply)
            reply_pkt.serialize()

            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      in_port=ofproto.OFPP_CONTROLLER,
                                      actions=actions,
                                      data=reply_pkt.data)
            datapath.send_msg(out)

        elif arp_pkt.opcode == arp.ARP_REPLY:
            # Learn new host info from ARP reply
            self.logger.info(f"Learned ARP: {src_ip} is at {src_mac} on port {in_port}")
            self.arp_table[src_ip] = (src_mac, in_port)

            # Send any buffered packets
            if src_ip in self.packet_buffer:
                for buffered_datapath, buffered_in_port, buffered_pkt in self.packet_buffer[src_ip]:
                    self.forward_ip(buffered_datapath, buffered_pkt, src_ip)
                del self.packet_buffer[src_ip]

        else:
            # Learn interface IP and MAC if it's a GARP (gratuitous ARP)
            if src_ip == dst_ip:
                self.interface_ips[src_ip] = (src_mac, in_port)

    def handle_ip(self, datapath, pkt, ip_pkt, eth, in_port):
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        # Learn source info
        self.arp_table[src_ip] = (eth.src, in_port)

        if dst_ip in self.arp_table:
            self.forward_ip(datapath, pkt, dst_ip)
        else:
            # Buffer the packet and initiate ARP request
            self.logger.info(f"ARP for unknown IP {dst_ip}, buffering packet")
            if dst_ip not in self.packet_buffer:
                self.packet_buffer[dst_ip] = []
            self.packet_buffer[dst_ip].append((datapath, in_port, pkt))

            self.send_arp_request(datapath, dst_ip, in_port)

    def forward_ip(self, datapath, pkt, dst_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)

        dst_mac, out_port = self.arp_table[dst_ip]

        # Find router MAC for this interface
        out_iface_ip = None
        for ip_addr, (mac, port) in self.interface_ips.items():
            if port == out_port:
                out_iface_ip = ip_addr
                eth_src_mac = mac
                break

        if not out_iface_ip:
            self.logger.warning(f"No interface IP found for port {out_port}")
            return

        # Modify Ethernet frame
        eth.src = eth_src_mac
        eth.dst = dst_mac

        pkt.serialize()
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=pkt.data)
        datapath.send_msg(out)

        # Install flow
        match = parser.OFPMatch(in_port=out_port,
                                eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_dst=dst_ip,
                                ipv4_src=ip.src)
        self.add_flow(datapath, 10, match, actions)

    def send_arp_request(self, datapath, target_ip, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Choose interface to send from
        for iface_ip, (iface_mac, port) in self.interface_ips.items():
            eth = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',
                                    src=iface_mac,
                                    ethertype=ether_types.ETH_TYPE_ARP)
            arp_req = arp.arp(opcode=arp.ARP_REQUEST,
                              src_mac=iface_mac, src_ip=iface_ip,
                              dst_mac='00:00:00:00:00:00', dst_ip=target_ip)

            req_pkt = packet.Packet()
            req_pkt.add_protocol(eth)
            req_pkt.add_protocol(arp_req)
            req_pkt.serialize()

            actions = [parser.OFPActionOutput(port)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      in_port=ofproto.OFPP_CONTROLLER,
                                      actions=actions,
                                      data=req_pkt.data)
            datapath.send_msg(out)
