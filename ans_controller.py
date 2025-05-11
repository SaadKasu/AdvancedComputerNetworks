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
        self.interface_ips = {
            # Router interfaces: IP → {mac, port}
            "10.0.1.1": {"mac": "00:00:00:00:01:01", "port": 1},
            "10.0.2.1": {"mac": "00:00:00:00:01:02", "port": 2},
            "192.168.1.1": {"mac": "00:00:00:00:01:03", "port": 3},
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
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
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

        # Learn sender IP → (MAC, port)
        self.arp_table[src_ip] = (src_mac, in_port)

        # If the router owns the IP, reply directly
        if dst_ip in self.interface_ips:
            self.logger.info("ARP request for router IP %s -> replying", dst_ip)
            mac = self.interface_ips[dst_ip]['mac']
            eth = ethernet.ethernet(dst=src_mac, src=mac,
                                    ethertype=ether_types.ETH_TYPE_ARP)
            arp_reply = arp.arp(opcode=arp.ARP_REPLY,
                                src_mac=mac, src_ip=dst_ip,
                                dst_mac=src_mac, dst_ip=src_ip)
            reply_pkt = packet.Packet()
            reply_pkt.add_protocol(eth)
            reply_pkt.add_protocol(arp_reply)
            reply_pkt.serialize()

            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      in_port=ofproto.OFPP_CONTROLLER,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      actions=actions,
                                      data=reply_pkt.data)
            datapath.send_msg(out)
            return

        # Proxy ARP if destination is known
        if dst_ip in self.arp_table:
            dst_mac, dst_port = self.arp_table[dst_ip]
            out_iface = self.interface_ips[
                next(ip for ip, info in self.interface_ips.items() if info["port"] == dst_port)
            ]
            mac = out_iface["mac"]

            self.logger.info("Proxy ARP: replying for %s with MAC %s", dst_ip, dst_mac)
            eth = ethernet.ethernet(dst=src_mac, src=mac,
                                    ethertype=ether_types.ETH_TYPE_ARP)
            arp_reply = arp.arp(opcode=arp.ARP_REPLY,
                                src_mac=dst_mac, src_ip=dst_ip,
                                dst_mac=src_mac, dst_ip=src_ip)
            reply_pkt = packet.Packet()
            reply_pkt.add_protocol(eth)
            reply_pkt.add_protocol(arp_reply)
            reply_pkt.serialize()

            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      in_port=ofproto.OFPP_CONTROLLER,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      actions=actions,
                                      data=reply_pkt.data)
            datapath.send_msg(out)

    def handle_ip(self, datapath, pkt, ip_pkt, eth, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        src_mac = eth.src

        # Learn source IP → (MAC, port)
        self.arp_table[src_ip] = (src_mac, in_port)

        # Drop if we don't know how to reach the destination
        if dst_ip not in self.arp_table:
            self.logger.info("Unknown destination IP %s — dropping packet", dst_ip)
            return

        dst_mac, out_port = self.arp_table[dst_ip]
        if out_port == in_port:
            self.logger.info("Skipping loop: out_port == in_port for IP %s", dst_ip)
            return

        # Get router MAC for out port
        out_iface_ip = next(ip for ip, info in self.interface_ips.items() if info["port"] == out_port)
        out_mac = self.interface_ips[out_iface_ip]["mac"]

        # Rewrite Ethernet header
        eth.src = out_mac
        eth.dst = dst_mac
        pkt.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  in_port=in_port,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  actions=actions,
                                  data=pkt.data)
        datapath.send_msg(out)

        # Install flow for future packets
        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )
        self.add_flow(datapath, 10, match, actions)
