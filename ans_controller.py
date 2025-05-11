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
        self.arp_table = {}  # IP → (MAC, port)

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
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_ARP and arp_pkt:
            self.handle_arp(datapath, pkt, arp_pkt, in_port)
        elif eth.ethertype == ether_types.ETH_TYPE_IP and ip_pkt:
            self.handle_ip(datapath, pkt, ip_pkt, in_port)

    def handle_arp(self, datapath, pkt, arp_pkt, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dst_ip = arp_pkt.dst_ip

        # Check if router owns the IP
        for port, ip in self.port_to_own_ip.items():
            if dst_ip == ip:
                # Reply to ARP
                src_mac = self.port_to_own_mac[port]
                eth = ethernet.ethernet(dst=arp_pkt.src_mac, src=src_mac,
                                        ethertype=ether_types.ETH_TYPE_ARP)
                arp_reply = arp.arp(opcode=arp.ARP_REPLY,
                                    src_mac=src_mac, src_ip=dst_ip,
                                    dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip)
                reply_pkt = packet.Packet()
                reply_pkt.add_protocol(eth)
                reply_pkt.add_protocol(arp_reply)
                reply_pkt.serialize()

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath,
                                          in_port=ofproto.OFPP_CONTROLLER,
                                          actions=actions,
                                          data=reply_pkt.data,
                                          buffer_id=ofproto.OFP_NO_BUFFER)
                datapath.send_msg(out)
                return

        # Router doesn't own the IP → flood ARP request
        self.logger.info("Flooding ARP request for unknown IP: %s", dst_ip)
        actions = [parser.OFPActionOutput(port)
                   for port in self.port_to_own_mac.keys() if port != in_port]
        out = parser.OFPPacketOut(datapath=datapath,
                                  in_port=in_port,
                                  actions=actions,
                                  data=pkt.data,
                                  buffer_id=ofproto.OFP_NO_BUFFER)
        datapath.send_msg(out)

    def handle_ip(self, datapath, pkt, ip_pkt, in_port):
        dst_ip = ip_pkt.dst
        src_ip = ip_pkt.src
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Learn the source
        eth = pkt.get_protocol(ethernet.ethernet)
        self.arp_table[src_ip] = (eth.src, in_port)

        # Check if destination IP is known
        if dst_ip in self.arp_table:
            dst_mac, out_port = self.arp_table[dst_ip]

            # Find router MAC for that port
            src_mac = self.port_to_own_mac[out_port]

            # Rewrite Ethernet frame
            eth.dst = dst_mac
            eth.src = src_mac
            pkt.serialize()

            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      in_port=in_port,
                                      actions=actions,
                                      data=pkt.data,
                                      buffer_id=ofproto.OFP_NO_BUFFER)
            datapath.send_msg(out)

            # Install flow
            match = parser.OFPMatch(in_port=in_port,
                                    eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_dst=dst_ip,
                                    ipv4_src=src_ip)
            self.add_flow(datapath, 1, match, actions)
        else:
            # Destination unknown: flood
            self.logger.info("Flooding IP packet for unknown destination: %s", dst_ip)
            flood_ports = [port for port in self.port_to_own_mac if port != in_port]
            actions = [parser.OFPActionOutput(port) for port in flood_ports]
            out = parser.OFPPacketOut(datapath=datapath,
                                      in_port=in_port,
                                      actions=actions,
                                      data=pkt.data,
                                      buffer_id=ofproto.OFP_NO_BUFFER)
            datapath.send_msg(out)
