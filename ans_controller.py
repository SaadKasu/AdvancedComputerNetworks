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
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp
from ryu.lib.packet import ether_types


class LearningRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningRouter, self).__init__(*args, **kwargs)
        self.arp_table = {}  # IP -> (MAC, port)

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
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self.handle_arp(datapath, arp_pkt, eth, in_port)
        elif ip_pkt:
            self.handle_ip(datapath, pkt, eth, ip_pkt, in_port)

    def handle_arp(self, datapath, arp_pkt, eth, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if arp_pkt.opcode == arp.ARP_REQUEST:
            for port, ip in self.port_to_own_ip.items():
                if arp_pkt.dst_ip == ip:
                    mac = self.port_to_own_mac[port]
                    self.logger.info("ARP request for %s → replying with %s", ip, mac)

                    arp_reply = arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=mac,
                        src_ip=ip,
                        dst_mac=arp_pkt.src_mac,
                        dst_ip=arp_pkt.src_ip
                    )
                    eth_reply = ethernet.ethernet(
                        dst=arp_pkt.src_mac,
                        src=mac,
                        ethertype=ether_types.ETH_TYPE_ARP
                    )
                    reply_pkt = packet.Packet()
                    reply_pkt.add_protocol(eth_reply)
                    reply_pkt.add_protocol(arp_reply)
                    reply_pkt.serialize()

                    actions = [parser.OFPActionOutput(in_port)]
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions,
                        data=reply_pkt.data
                    )
                    datapath.send_msg(out)

        elif arp_pkt.opcode == arp.ARP_REPLY:
            self.arp_table[arp_pkt.src_ip] = (arp_pkt.src_mac, in_port)
            self.logger.info("Learned ARP: %s → %s", arp_pkt.src_ip, arp_pkt.src_mac)

    def handle_ip(self, datapath, pkt, eth, ip_pkt, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Save source MAC and IP
        self.arp_table[ip_pkt.src] = (eth.src, in_port)

        # ICMP echo-reply handling
        if ip_pkt.dst in self.port_to_own_ip.values():
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                self.logger.info("Responding to ICMP echo from %s", ip_pkt.src)
                self.send_icmp_reply(datapath, pkt, eth, ip_pkt, in_port)
            return

        # Route to known IP
        if ip_pkt.dst in self.arp_table:
            dst_mac, out_port = self.arp_table[ip_pkt.dst]
            for port, ip in self.port_to_own_ip.items():
                if ip.startswith(ip_pkt.dst.rsplit('.', 1)[0]):
                    src_mac = self.port_to_own_mac[port]
                    break
            else:
                src_mac = eth.dst  # Fallback

            eth.src = src_mac
            eth.dst = dst_mac
            pkt.serialize()

            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=pkt.data
            )
            datapath.send_msg(out)
        else:
            self.logger.info("Unknown destination %s, sending ARP", ip_pkt.dst)
            self.send_arp_request(datapath, ip_pkt.dst, in_port)

    def send_icmp_reply(self, datapath, pkt, eth, ip_pkt, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        icmp_pkt = pkt.get_protocol(icmp.icmp)
        ip_dst = ip_pkt.src
        ip_src = ip_pkt.dst

        for port, ip in self.port_to_own_ip.items():
            if ip == ip_src:
                mac_src = self.port_to_own_mac[port]
                break

        eth_reply = ethernet.ethernet(
            dst=eth.src,
            src=mac_src,
            ethertype=eth.ethertype
        )
        ip_reply = ipv4.ipv4(
            dst=ip_dst,
            src=ip_src,
            proto=ip_pkt.proto
        )
        icmp_reply = icmp.icmp(
            type_=icmp.ICMP_ECHO_REPLY,
            code=0,
            csum=0,
            data=icmp_pkt.data
        )

        reply_pkt = packet.Packet()
        reply_pkt.add_protocol(eth_reply)
        reply_pkt.add_protocol(ip_reply)
        reply_pkt.add_protocol(icmp_reply)
        reply_pkt.serialize()

        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=reply_pkt.data
        )
        datapath.send_msg(out)

    def send_arp_request(self, datapath, dst_ip, out_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        gateway_ip = self.port_to_own_ip[out_port]
        gateway_mac = self.port_to_own_mac[out_port]

        eth_req = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',
                                    src=gateway_mac,
                                    ethertype=ether_types.ETH_TYPE_ARP)
        arp_req = arp.arp(opcode=arp.ARP_REQUEST,
                          src_mac=gateway_mac,
                          src_ip=gateway_ip,
                          dst_mac='00:00:00:00:00:00',
                          dst_ip=dst_ip)
        pkt = packet.Packet()
        pkt.add_protocol(eth_req)
        pkt.add_protocol(arp_req)
        pkt.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data
        )
        datapath.send_msg(out)
