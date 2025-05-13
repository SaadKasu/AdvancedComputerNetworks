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
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types
import ipaddress


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.mac_to_port = {}
        # Router port MACs assumed by the controller
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }
        # Router port (gateways) IP addresses assumed by the controller
        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }
        
        self.pending_packets = {}
        self.arp_table = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)#This decorator tells Ryu when the decorated function should be called. The first argument of the decorator indicates which type of event this function should be called for. The second argument indicates the state of the switch. You probably want to ignore packet_in messages before the negotiation between Ryu and the switch is finished.
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        
        if dpid==3:
            # Handle ARP packets
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                self.handle_arp(datapath,pkt, in_port, eth)
            # Handle IP packets
            elif eth.ethertype == ether_types.ETH_TYPE_IP:
                self.handle_ip(datapath, pkt,in_port, eth)
            return

        ## SWITCH FUNCTIONALITY

        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port == ofproto.OFPP_FLOOD:
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, ofproto.OFP_DEFAULT_PRIORITY, datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src), actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, ofproto.OFP_DEFAULT_PRIORITY, datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src), actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    def handle_arp(self, datapath, pkt, in_port, eth):
        
        arp_pkt = pkt.get_protocol(arp.arp)
                
        self.logger.info("Handling an ARP SRC IP : %s DST IP : %s In_Port : %s SRC Mac : %s DST Mac : %s",arp_pkt.src_ip,arp_pkt.dst_ip, in_port, eth.src, eth.dst)

        if not (arp_pkt.src_ip == '192.168.1.2' and arp_pkt.dst_ip == '192.168.1.1') or arp_pkt.dst_ip == '192.168.1.2':
            self.logger.info("Blocking unsolicited ARP involving ext host")
            return

        if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.port_to_own_ip[in_port]:
            self.send_arp_reply(datapath, pkt, in_port, eth, arp_pkt)
        elif arp_pkt.opcode == arp.ARP_REQUEST: 
            self.send_arp_request(datapath, pkt, in_port, eth, arp_pkt)
        else:
            self.handle_arp_reply(datapath, pkt, in_port, eth, arp_pkt)


    def send_arp_reply(self, datapath, pkt, in_port, eth, arp_pkt):

        self.logger.info("Inside The ARP if condition, Learn The Mac Of The Router")

        self.arp_table[arp_pkt.src_ip] = {'mac': eth.src, 'port': in_port}
        
        src_mac = self.port_to_own_mac[in_port]
        src_ip = self.port_to_own_ip[in_port]
        dst_ip = arp_pkt.src_ip
        dst_mac = eth.src
        dst = eth.src
        src = src_mac
        self.logger.info("ARP Reply src_mac : %s SRC IP : %s DST IP : %s DST Mac : %s SRC : %s DST : %s",src_mac, src_ip, dst_ip, dst_mac, src, dst)          
        
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            ethertype = eth.ethertype,
            dst = dst_mac,
            src = src_mac
        ))
        arp_reply.add_protocol(arp.arp(
            opcode = arp.ARP_REPLY,
            src_mac = src_mac,
            src_ip = src_ip,
            dst_mac = dst_mac,
            dst_ip = dst_ip
        ))
        arp_reply.serialize()

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions, data=arp_reply.data,
                                  buffer_id=ofproto.OFP_NO_BUFFER)
        datapath.send_msg(out)

    def send_arp_request(self, datapath, pkt, in_port, eth, arp_pkt):

        self.logger.info("Inside The ARP else if condition, Learn The Mac Of the Host, Broadcasting the message and adding it to the buffer In Port:%s DST_IP : %s SRC_IP : %s",in_port, arp_pkt.dst_ip, arp_pkt.src_ip)

        out_port = self.get_out_port(arp_pkt.dst_ip)

        src_mac = self.port_to_own_mac[out_port]
        src_ip = self.port_to_own_ip[out_port]
        dst_ip = arp_pkt.dst_ip
        dst_mac='00:00:00:00:00:00'
        dst='ff:ff:ff:ff:ff:ff'
        
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=dst,
            src=src_mac
        ))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac='00:00:00:00:00:00',
            dst_ip=dst_ip
        ))
        pkt.serialize()

        self.pending_packets.setdefault(dst_ip, []).append((in_port, eth.src, arp_pkt.src_ip))

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions, data=pkt.data,
                                  buffer_id=ofproto.OFP_NO_BUFFER)
        datapath.send_msg(out) 

    def handle_arp_reply(self, datapath, pkt, in_port, eth, arp_pkt):
        self.logger.info("Handling an ARP Reply SRC IP : %s DST IP : %s In_Port : %s SRC Mac : %s DST Mac : %s",arp_pkt.src_ip,arp_pkt.dst_ip, in_port, eth.src, eth.dst)
        
        src_ip = arp_pkt.src_ip

        self.arp_table[src_ip] = {'mac': eth.src, 'port': in_port}
        
        if src_ip in self.pending_packets:
            self.logger.info("Found a packet with source ip : %s",src_ip)
            for out_port, dst, dst_ip in self.pending_packets[src_ip]:
                self.logger.info("Generating a ARP Reply for request from : Port : %s IP : %s MAC : %s",out_port, dst_ip, dst_ip)
                arp_reply = packet.Packet()
                arp_reply.add_protocol(ethernet.ethernet(
                    ethertype = eth.ethertype,
                    dst = dst,
                    src = eth.src
                ))
                arp_reply.add_protocol(arp.arp(
                    opcode = arp.ARP_REPLY,
                    src_mac = eth.src,
                    src_ip = src_ip,
                    dst_mac = dst,
                    dst_ip = dst_ip
                ))
                arp_reply.serialize()

                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                actions = [parser.OFPActionOutput(out_port)]
                out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_CONTROLLER,
                                          actions=actions, data=arp_reply.data,
                                          buffer_id=ofproto.OFP_NO_BUFFER)
                datapath.send_msg(out)
            del self.pending_packets[arp_pkt.src_ip]

    def handle_ip(self, datapath, pkt, in_port, eth):
        
        ip_pkt = pkt.get_protocol(ipv4.ipv4)        
    
        self.logger.info("Handling an IP Request SRC IP : %s DST IP : %s In_Port : %s",ip_pkt.src,ip_pkt.dst, in_port)

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        self.arp_table[src_ip] = {'mac': eth.src, 'port': in_port}

        dst_entry = self.arp_table.get(dst_ip)
        if not dst_entry:
            self.logger.info("No ARP entry for %s, sending ARP request on port %d", dst_ip, in_port)

            arp_pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_ARP,
                dst='ff:ff:ff:ff:ff:ff',
                src=eth.src
            ))
            arp_pkt.add_protocol(arp.arp(
                opcode=arp.ARP_REQUEST,
                src_mac=eth.src,
                src_ip=src_ip,
                dst_mac='00:00:00:00:00:00',
                dst_ip=dst_ip
            ))
            arp_pkt.serialize()

            self.send_arp_request(datapath, pkt, in_port, eth, arp_pkt.get_protocol(arp.arp))
            return
        
        eth_pkt = ethernet.ethernet(dst=dst_entry['mac'], src=self.port_to_own_mac[dst_entry['port']], ethertype=eth.ethertype)

        ipv4_pkt = ipv4.ipv4(dst=ip_pkt.dst, src=ip_pkt.src, proto=ip_pkt.proto)

        self.logger.info("IP Packet : %s",ipv4_pkt)
        
        pkt.add_protocol(eth_pkt)
        pkt.add_protocol(ipv4_pkt)        
    
        pkt.serialize()

        actions = [parser.OFPActionSetField(eth_src=self.port_to_own_mac[dst_entry['port']]),
                                parser.OFPActionSetField(eth_dst=dst_entry['mac']),
                                parser.OFPActionOutput(dst_entry['port'])]
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip_pkt.src,
            ipv4_dst=ip_pkt.dst
        )
        
        self.add_flow(datapath, ofproto.OFP_DEFAULT_PRIORITY, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
            actions=actions, data=pkt.data)
        datapath.send_msg(out)


    def get_out_port(self, dst_ip):
        if dst_ip.startswith('10.0.1'):
            return 1
        elif dst_ip.startswith('10.0.2'):
            return 2
        return 3
