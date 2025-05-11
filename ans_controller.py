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
from ryu.lib.packet import packet, ethernet, arp, ipv4, ether_types
from ryu.ofproto import ofproto_v1_3

class SimpleRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleRouter, self).__init__(*args, **kwargs)

        # Define router's interface IP and MAC per port
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

        # ARP table: IP -> MAC
        self.arp_table = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
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

        if arp_pkt:
            self.handle_arp(datapath, pkt, arp_pkt, in_port)
        elif ip_pkt:
            self.handle_ip(datapath, pkt, ip_pkt, in_port)

    def handle_arp(self, datapath, pkt, arp_pkt, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if arp_pkt.opcode == arp.ARP_REQUEST:
            target_ip = arp_pkt.dst_ip

            # Check if this router has the target IP on any interface
            for port, ip_addr in self.port_to_own_ip.items():
                if target_ip == ip_addr:
                    mac_addr = self.port_to_own_mac[port]
                    self.logger.info("Replying to ARP request for %s on port %s", target_ip, port)

                    arp_reply = arp.arp(opcode=arp.ARP_REPLY,
                                        src_mac=mac_addr,
                                        src_ip=target_ip,
                                        dst_mac=arp_pkt.src_mac,
                                        dst_ip=arp_pkt.src_ip)

                    eth_reply = ethernet.ethernet(dst=arp_pkt.src_mac,
                                                  src=mac_addr,
                                                  ethertype=ether_types.ETH_TYPE_ARP)

                    reply_pkt = packet.Packet()
                    reply_pkt.add_protocol(eth_reply)
                    reply_pkt.add_protocol(arp_reply)
                    reply_pkt.serialize()

                    actions = [parser.OFPActionOutput(in_port)]
                    out = parser.OFPPacketOut(datapath=datapath,
                                              buffer_id=ofproto.OFP_NO_BUFFER,
                                              in_port=ofproto.OFPP_CONTROLLER,
                                              actions=actions,
                                              data=reply_pkt.data)
                    datapath.send_msg(out)
                    return

        elif arp_pkt.opcode == arp.ARP_REPLY:
            # Store the sender IP → MAC
            self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
            self.logger.info("ARP reply learned: %s -> %s", arp_pkt.src_ip, arp_pkt.src_mac)

    def handle_ip(self, datapath, pkt, ip_pkt, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dst_ip = ip_pkt.dst
        src_ip = ip_pkt.src

        # Learn the source IP → MAC
        eth = pkt.get_protocol(ethernet.ethernet)
        self.arp_table[src_ip] = eth.src

        # Determine outgoing interface by longest-prefix match
        out_port = None
        out_mac = None
        for port, gateway_ip in self.port_to_own_ip.items():
            if dst_ip.startswith(gateway_ip.rsplit('.', 1)[0]):  # crude /24 match
                out_port = port
                out_mac = self.port_to_own_mac[port]
                break

        if out_port is None:
            self.logger.info("No route to %s", dst_ip)
            return

        dst_mac = self.arp_table.get(dst_ip)
        if not dst_mac:
            self.logger.info("No ARP entry for %s; waiting for ARP resolution", dst_ip)
            return

        # Modify Ethernet header
        eth.dst = dst_mac
        eth.src = out_mac
        pkt.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port,
                                  actions=actions,
                                  data=pkt.data)
        datapath.send_msg(out)
