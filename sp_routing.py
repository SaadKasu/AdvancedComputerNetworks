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

#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
import heapq
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

import topo

class SPRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        
        # Initialize the topology with #ports=4
        self.topo_net = topo.Fattree(4)
        self.dpid_neighbours = {}
        self.distance_between_switches = {}
        self.path_between_switches = {}

    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):

        # Switches and links in the network
        switches = get_switch(self, None)
        links = get_link(self, None)

        for switch in switches :
            self.dpid_neighbours.setdefault(switch.dp.id, {})

        for link in links:
            src = link.src
            dst = link.dst
    
            if src.dpid not in self.dpid_neighbours[dst.dpid]:
                self.dpid_neighbours[dst.dpid][src.dpid] = dst.port_no
            
            if dst.dpid not in self.dpid_neighbours[src.dpid]:
                self.dpid_neighbours[src.dpid][dst.dpid] = src.port_no

        for switch in switches:
            self.path_between_switches.setdefault(switch.dp.id,{})
            self.distance_between_switches.setdefault(switch.dp.id,{})
            for switch2 in switches:
                self.distance_between_switches[switch.dp.id][switch2.dp.id] = float('inf')
            #Call dijkstra
            self.dijkstra(switch.dp.id, switches)

    def dijkstra(self, source, switches):
        dist = {}
        prev = {}
        for switch in switches :
            dist[switch.dp.id] = float('inf')
            prev[switch.dp.id] = (None,None)
        dist[source] = 0
        queue = [(0,source)]
        visitedNodes = []
        
        while queue : 
            cost, u = heapq.heappop(queue)
            visitedNodes.append(u)
            self.distance_between_switches[source][u] = dist[u]
            for neighbour in self.dpid_neighbours[u]:
                nextDist = dist[u] + 1
                if nextDist < dist[neighbour] and neighbour not in visitedNodes :
                    dist[neighbour] = nextDist
                    prev[neighbour] = (u, self.dpid_neighbours[u][neighbour])
                    heapq.heappush(queue, (nextDist, neighbour))

        for switch in switches :
            dest = switch.dp.id
            path = []
            previousNode = prev[dest]
            self.path_between_switches[source].setdefault(dest,[])
            while dest is not None :
                path.insert(0, previousNode)
                dest = prev[dest][0]

            self.path_between_switches[source][switch.dp.id] = path
            print("Path between - ",source, " and Destination - ",switch.dp.id, " is - ",path)
        
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install entry-miss flow entry
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


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # TODO: handle new packets at the controller
