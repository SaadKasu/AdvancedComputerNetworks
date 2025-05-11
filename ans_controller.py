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
        self.arp_table = {}         # IP → (MAC, port)
        self.router_ips = set()     # Track all IPs owned by the router
        self.router_mac_by_port = {} # port → MAC

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Send all unmatched packets to controller
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
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # Ignore LLDP

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth.src.startswith('00:00:00:00:01'):  # crude check for router's MAC
            self.router_mac_by_port[in_port] = eth.src

        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = (arp_pkt.src_mac, in_port)
            if arp_pkt.opcode == arp.ARP_REQUEST:
                if arp_pkt.dst_ip in self.router_ips:
                    self.reply_arp(datapath, in_port, arp_pkt)
        elif ip_pkt:
            self.arp_table[ip_pkt.src] = (eth.src, in_port)
            if ip_pkt.dst in self.arp_table:
                dst_mac, out_port = self.arp_table[ip_pkt.dst]
                self.forward_ip(datapath, pkt, eth, ip_pkt, in_port, out_port, dst_mac)
            else:
                self.logger.info("Unknown dst %s. Sending ARP.", ip_pkt.dst)
                self.send_arp_request(datapath, ip_pkt.dst, in_port)

    def reply_arp(self, datapath, port, arp_req):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mac = self.router_mac_by_port.get(port)
        if not mac:
            self.logger.warning("No MAC known for port %d", port)
            return

        self.router_ips.add(arp_req.dst_ip)

        eth = ethernet.ethernet(dst=arp_req.src_mac, src=mac,
                                ethertype=ether_types.ETH_TYPE_ARP)
        arp_reply = arp.arp(opcode=arp.ARP_REPLY,
                            src_mac=mac, src_ip=arp_req.dst_ip,
                            dst_mac=arp_req.src_mac, dst_ip=arp_req.src_ip)
        pkt = packet.Packet()
        pkt.add_protocol(eth)
        pkt.add_protocol(arp_reply)
        pkt.serialize()

        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions, data=pkt.data)
        datapath.send_msg(out)

    def forward_ip(self, datapath, pkt, eth, ip_pkt, in_port, out_port, dst_mac):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        new_eth = ethernet.ethernet(dst=dst_mac,
                                    src=self.router_mac_by_port.get(out_port, eth.src),
                                    ethertype=eth.ethertype)
        pkt.protocols[0] = new_eth
        pkt.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  in_port=in_port,
                                  actions=actions,
                                  data=pkt.data,
                                  buffer_id=ofproto.OFP_NO_BUFFER)
        datapath.send_msg(out)

        match = parser.OFPMatch(in_port=in_port,
                                eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=ip_pkt.src,
                                ipv4_dst=ip_pkt.dst)
        self.add_flow(datapath, 1, match, actions)

    def send_arp_request(self, datapath, dst_ip, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        src_mac = self.router_mac_by_port.get(in_port)
        src_ip = None
        for ip in self.router_ips:
            if ip.startswith(dst_ip[:dst_ip.rfind('.')]):  # crude subnet match
                src_ip = ip
                break

        if not src_mac or not src_ip:
            self.logger.warning("No source IP/MAC to send ARP from")
            return

        eth = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff', src=src_mac,
                                ethertype=ether_types.ETH_TYPE_ARP)
        arp_req = arp.arp(opcode=arp.ARP_REQUEST,
                          src_mac=src_mac, src_ip=src_ip,
                          dst_mac='00:00:00:00:00:00', dst_ip=dst_ip)

        pkt = packet.Packet()
        pkt.add_protocol(eth)
        pkt.add_protocol(arp_req)
        pkt.serialize()

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  in_port=in_port,
                                  actions=actions,
                                  data=pkt.data,
                                  buffer_id=ofproto.OFP_NO_BUFFER)
        datapath.send_msg(out)
