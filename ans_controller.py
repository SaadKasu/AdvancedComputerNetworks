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
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types
import ipaddress


class StaticLearningRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(StaticLearningRouter, self).__init__(*args, **kwargs)

        # Static router port MACs
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }

        # Static router port IPs (gateways)
        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }

        # Subnet mapping for routing
        self.subnet_map = {
            "10.0.1.0/24": 1,
            "10.0.2.0/24": 2,
            "192.168.1.0/24": 3
        }

        # Dynamic ARP table: IP → {mac, port}
        self.arp_table = {}

        self.blocked_ip = "192.168.1.2"

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        # Default rule: send unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(dp, 0, match, actions)

    def add_flow(self, dp, priority, match, actions):
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
        dp.send_msg(mod)

    def get_out_port_for_ip(self, dst_ip):
        for subnet_str, port in self.subnet_map.items():
            if ipaddress.IPv4Address(dst_ip) in ipaddress.IPv4Network(subnet_str):
                return port
        return None

    def get_iface_info(self, port):
        return {
            'mac': self.port_to_own_mac[port],
            'ip': self.port_to_own_ip[port]
        }

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        self.logger.info("Packet in on port %d | src=%s dst=%s ethertype=0x%04x",
                         in_port, eth.src, eth.dst, eth.ethertype)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info("Handling ARP packet")
            self.handle_arp(pkt, dp, in_port)
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            self.logger.info("Handling IPv4 packet from %s to %s", src_ip, dst_ip)

            if src_ip == self.blocked_ip or dst_ip == self.blocked_ip:
                self.logger.warning("Dropped packet from/to blocked IP %s", self.blocked_ip)
                return

            self.logger.info("Learning ARP: %s is at %s (via port %d)", src_ip, eth.src, in_port)
            self.arp_table[src_ip] = {'mac': eth.src, 'port': in_port}

            out_port = self.get_out_port_for_ip(dst_ip)
            if out_port is None:
                self.logger.warning("No route to %s", dst_ip)
                return

            dst_entry = self.arp_table.get(dst_ip)
            if not dst_entry:
                self.logger.info("No ARP entry for %s, sending ARP request on port %d", dst_ip, out_port)
                self.send_arp_request(dp, out_port, dst_ip)
                return

            out_iface = self.get_iface_info(out_port)

            self.logger.info("Forwarding packet to %s via port %d | MAC: %s", dst_ip, dst_entry['port'], dst_entry['mac'])

            actions = [
                parser.OFPActionSetField(eth_src=out_iface['mac']),
                parser.OFPActionSetField(eth_dst=dst_entry['mac']),
                parser.OFPActionOutput(dst_entry['port'])
            ]

            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip
            )
            self.add_flow(dp, 10, match, actions)

            out = parser.OFPPacketOut(
                datapath=dp,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            dp.send_msg(out)

    def handle_arp(self, pkt, dp, in_port):
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        arp_pkt = pkt.get_protocol(arp.arp)

        self.logger.info("Received ARP %s from %s (%s) to %s",
                         "REQUEST" if arp_pkt.opcode == arp.ARP_REQUEST else "REPLY",
                         arp_pkt.src_ip, arp_pkt.src_mac, arp_pkt.dst_ip)

        # Learn source MAC/IP
        self.logger.info("Learning ARP: %s is at %s (via port %d)", arp_pkt.src_ip, arp_pkt.src_mac, in_port)
        self.arp_table[arp_pkt.src_ip] = {'mac': arp_pkt.src_mac, 'port': in_port}

        # Handle ARP request for router interface
        for port, own_ip in self.port_to_own_ip.items():
            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == own_ip:
                own_mac = self.port_to_own_mac[port]
                self.logger.info("Replying to ARP request for %s on port %d", own_ip, port)

                arp_reply = packet.Packet()
                arp_reply.add_protocol(ethernet.ethernet(
                    ethertype=ether_types.ETH_TYPE_ARP,
                    dst=arp_pkt.src_mac,
                    src=own_mac
                ))
                arp_reply.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=own_mac,
                    src_ip=own_ip,
                    dst_mac=arp_pkt.src_mac,
                    dst_ip=arp_pkt.src_ip
                ))
                arp_reply.serialize()

                out = parser.OFPPacketOut(
                    datapath=dp,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=[parser.OFPActionOutput(in_port)],
                    data=arp_reply.data
                )
                dp.send_msg(out)
                return

        # If it's an ARP reply, we’ve already learned it above

    def send_arp_request(self, dp, out_port, target_ip):
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        iface = self.get_iface_info(out_port)
        src_mac = iface['mac']
        src_ip = iface['ip']

        self.logger.info("Sending ARP request for %s from %s (%s) via port %d",
                         target_ip, src_ip, src_mac, out_port)

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst='ff:ff:ff:ff:ff:ff',
            src=src_mac
        ))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac='00:00:00:00:00:00',
            dst_ip=target_ip
        ))
        pkt.serialize()

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(out_port)],
            data=pkt.data
        )
        dp.send_msg(out)
