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
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4
from ryu.lib.packet import ether_types
from ryu.lib import mac

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Initialize data structures
        self.mac_to_port = {}
        self.arp_table = {}  # IP -> MAC address table

        # Define gateway IPs and their connected switches (port to gateway IP and MAC)
        self.gateways = {
            '10.0.1.1': '00:00:00:00:01:01',  # Gateway for subnet 10.0.1.0/24
            '10.0.2.1': '00:00:00:00:01:02',  # Gateway for subnet 10.0.2.0/24
            '192.168.1.1': '00:00:00:00:01:03'  # Gateway for Internet/other subnet
        }

        # Static routes for routing between subnets
        self.routing_table = {
            '10.0.2.0/24': '10.0.1.1',  # Route to 10.0.2.0/24 via gateway 10.0.1.1
            '10.0.1.0/24': '10.0.2.1',  # Route to 10.0.1.0/24 via gateway 10.0.2.1
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install a table-miss flow entry (misses go to the controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # Ignore LLDP packets

        dst = eth.dst
        src = eth.src
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # Learn MAC addresses
        self.mac_to_port[dpid][src] = in_port

        # Handle ARP packets (to populate the ARP table)
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.logger.info(f"Received ARP packet: {arp_pkt.src_ip} -> {arp_pkt.dst_ip}")
            self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac

            if arp_pkt.opcode == arp.ARP_REQUEST:
                # If this is an ARP request, reply with ARP_REPLY if we are the target
                if arp_pkt.dst_ip in self.gateways:
                    self._send_arp_reply(datapath, pkt, arp_pkt, in_port)
                elif arp_pkt.dst_ip not in self.arp_table:
                    # ARP request is for a host we do not know
                    self._send_arp_reply(datapath, pkt, arp_pkt, in_port)
                return

        # Handle IPv4 packet forwarding (routing)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            dst_ip = ip_pkt.dst
            if dst_ip in self.gateways:
                # If the destination is a local gateway, use the MAC address from the gateway table
                dst_mac = self.gateways[dst_ip]
                out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
            else:
                # Use routing table for routing between different subnets
                next_hop_ip = self.routing_table.get(dst_ip)
                if next_hop_ip and next_hop_ip in self.arp_table:
                    dst_mac = self.arp_table[next_hop_ip]
                    out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
                else:
                    out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

            # Forward the packet to the appropriate port
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    def _send_arp_reply(self, datapath, pkt, arp_req, port):
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        src_mac = self.gateways.get(arp_req.dst_ip)
        if not src_mac:
            return

        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=arp_req.src_mac,
            src=src_mac))
        arp_reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            src_ip=arp_req.dst_ip,
            dst_mac=arp_req.src_mac,
            dst_ip=arp_req.src_ip))

        arp_reply.serialize()
        actions = [datapath.ofproto_parser.OFPActionOutput(port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions, data=arp_reply.data)
        datapath.send_msg(out)

