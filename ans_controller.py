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
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, ether_types
from ryu.ofproto import ofproto_v1_3
from ryu.lib import addrconv
import ipaddress

class PatchedRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PatchedRouter, self).__init__(*args, **kwargs)

        # Define interface MAC and IP per port
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",  # Subnet A
            2: "00:00:00:00:01:02",  # Subnet B
            3: "00:00:00:00:01:03"   # Subnet C
        }

        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }

        self.arp_table = {}  # IP → MAC

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
            for port, ip_addr in self.port_to_own_ip.items():
                if target_ip == ip_addr:
                    mac_addr = self.port_to_own_mac[port]
                    self.logger.info("Replying to ARP request for %s", target_ip)

                    eth_reply = ethernet.ethernet(dst=arp_pkt.src_mac,
                                                  src=mac_addr,
                                                  ethertype=ether_types.ETH_TYPE_ARP)
                    arp_reply = arp.arp(opcode=arp.ARP_REPLY,
                                        src_mac=mac_addr,
                                        src_ip=target_ip,
                                        dst_mac=arp_pkt.src_mac,
                                        dst_ip=arp_pkt.src_ip)

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

        elif arp_pkt.opcode == arp.ARP_REPLY:
            self.logger.info("Received ARP reply: %s -> %s", arp_pkt.src_ip, arp_pkt.src_mac)
            self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac

    def handle_ip(self, datapath, pkt, ip_pkt, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dst_ip = ip_pkt.dst
        src_ip = ip_pkt.src

        # Learn sender MAC
        eth = pkt.get_protocol(ethernet.ethernet)
        self.arp_table[src_ip] = eth.src

        # Find outgoing port based on destination IP (longest prefix match)
        out_port, out_mac, out_ip = None, None, None
        for port, ip_addr in self.port_to_own_ip.items():
            net = ipaddress.ip_network(ip_addr + '/24', strict=False)
            if ipaddress.ip_address(dst_ip) in net:
                out_port = port
                out_mac = self.port_to_own_mac[port]
                out_ip = ip_addr
                break

        if dst_ip in self.port_to_own_ip.values():
            # This router is the destination — respond to ICMP
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                self.logger.info("ICMP Echo Request to router: %s", dst_ip)
                icmp_reply = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                       code=0,
                                       csum=0,
                                       data=icmp_pkt.data)

                ip_reply = ipv4.ipv4(dst=src_ip,
                                     src=dst_ip,
                                     proto=ip_pkt.proto)

                eth_reply = ethernet.ethernet(dst=eth.src,
                                              src=eth.dst,
                                              ethertype=ether_types.ETH_TYPE_IP)

                reply_pkt = packet.Packet()
                reply_pkt.add_protocol(eth_reply)
                reply_pkt.add_protocol(ip_reply)
                reply_pkt.add_protocol(icmp_reply)
                reply_pkt.serialize()

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=ofproto.OFPP_CONTROLLER,
                                          actions=actions,
                                          data=reply_pkt.data)
                datapath.send_msg(out)
            return

        if out_port is None:
            self.logger.warning("No route to %s", dst_ip)
            return

        dst_mac = self.arp_table.get(dst_ip)
        if not dst_mac:
            self.logger.info("MAC for %s not known — sending ARP request", dst_ip)
            self.send_arp_request(datapath, out_port, out_mac, out_ip, dst_ip)
            return

        # Rewrite Ethernet header and forward
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

    def send_arp_request(self, datapath, port, src_mac, src_ip, target_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        self.logger.info("Sending ARP request: who has %s?", target_ip)

        eth_req = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',
                                    src=src_mac,
                                    ethertype=ether_types.ETH_TYPE_ARP)

        arp_req = arp.arp(opcode=arp.ARP_REQUEST,
                          src_mac=src_mac,
                          src_ip=src_ip,
                          dst_mac='00:00:00:00:00:00',
                          dst_ip=target_ip)

        pkt = packet.Packet()
        pkt.add_protocol(eth_req)
        pkt.add_protocol(arp_req)
        pkt.serialize()

        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  actions=actions,
                                  data=pkt.data)
        datapath.send_msg(out)
