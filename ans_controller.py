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
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib.packet import ether_types

class StaticRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(StaticRouter, self).__init__(*args, **kwargs)

        # Router port info
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

        self.arp_table = {}  # IP -> (MAC, port)
        self.packet_buffer = {}  # IP -> list of (datapath, msg, in_port)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Send unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
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

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, in_port, eth, arp_pkt)
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            self.handle_ip(datapath, msg, in_port, eth, ip_pkt)

    def handle_arp(self, datapath, in_port, eth, arp_pkt):
        if arp_pkt.opcode == arp.ARP_REQUEST:
            # Reply if it's for the router
            for port, ip in self.port_to_own_ip.items():
                if arp_pkt.dst_ip == ip:
                    src_mac = self.port_to_own_mac[port]
                    dst_mac = eth.src
                    arp_reply = packet.Packet()
                    arp_reply.add_protocol(ethernet.ethernet(
                        ethertype=ether_types.ETH_TYPE_ARP,
                        dst=dst_mac,
                        src=src_mac
                    ))
                    arp_reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=src_mac,
                        src_ip=ip,
                        dst_mac=dst_mac,
                        dst_ip=arp_pkt.src_ip
                    ))
                    arp_reply.serialize()
                    actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions,
                        data=arp_reply.data
                    )
                    datapath.send_msg(out)
        elif arp_pkt.opcode == arp.ARP_REPLY:
            # Learn MAC address
            self.arp_table[arp_pkt.src_ip] = (arp_pkt.src_mac, in_port)

            # Send any buffered packets
            if arp_pkt.src_ip in self.packet_buffer:
                for datapath, msg, in_port in self.packet_buffer[arp_pkt.src_ip]:
                    self.forward_ip(datapath, msg, in_port, arp_pkt.src_mac)
                del self.packet_buffer[arp_pkt.src_ip]

    def handle_ip(self, datapath, msg, in_port, eth, ip_pkt):
        dst_ip = ip_pkt.dst

        # Determine output port
        out_port = None
        for port, subnet_ip in self.port_to_own_ip.items():
            if self.same_subnet(dst_ip, subnet_ip):
                out_port = port
                break

        if not out_port:
            # Assume we forward to destination IP directly
            out_port = self.route_ip(dst_ip)

        # ARP lookup
        if dst_ip in self.arp_table:
            next_mac, next_port = self.arp_table[dst_ip]
            self.forward_ip(datapath, msg, in_port, next_mac)
        else:
            # Send ARP request
            self.packet_buffer.setdefault(dst_ip, []).append((datapath, msg, in_port))
            self.send_arp_request(datapath, out_port, dst_ip)

    def forward_ip(self, datapath, msg, in_port, dst_mac):
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        out_port = self.route_ip(ip_pkt.dst)
        src_mac = self.port_to_own_mac[out_port]

        actions = [
            parser.OFPActionSetField(eth_src=src_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip_pkt.src,
            ipv4_dst=ip_pkt.dst
        )
        self.add_flow(datapath, 10, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)

    def send_arp_request(self, datapath, out_port, target_ip):
        src_ip = self.port_to_own_ip[out_port]
        src_mac = self.port_to_own_mac[out_port]

        arp_req = packet.Packet()
        arp_req.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            src=src_mac,
            dst='ff:ff:ff:ff:ff:ff'
        ))
        arp_req.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac='00:00:00:00:00:00',
            dst_ip=target_ip
        ))
        arp_req.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=arp_req.data
        )
        datapath.send_msg(out)

    def route_ip(self, dst_ip):
        if dst_ip.startswith('10.0.1.'):
            return 1
        elif dst_ip.startswith('10.0.2.'):
            return 2
        elif dst_ip.startswith('192.168.1.'):
            return 3
        return 1  # Default route

    def same_subnet(self, ip1, ip2):
        return ip1.split('.')[:3] == ip2.split('.')[:3]
