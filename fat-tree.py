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

import os
import subprocess
import time

import mininet
import mininet.clean
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.link import TCLink
from mininet.node import Node, OVSKernelSwitch, RemoteController
from mininet.topo import Topo
from mininet.util import waitListening, custom

from topo import Fattree

num_ports=4

class FattreeNet(Topo):
    """
    Create a fat-tree network in Mininet
    """

    def __init__(self, ft_topo):
        self.topo = ft_topo
        self.servers = []
        self.node_map = {}
        self.name_dpId_map = {}
        links = set([])
        """
        self.core_switches = []
        self.aggr_switches = []
        self.edge_switches = []
        self.all_links = []
        """
        half_ports = int(num_ports/2)
        core_count = 0
        aggr_count = half_ports
        pod_count = 0
        edge_count = 0
        server_count = 0
        core_switch = 0
        aggr_switch = 0
        edge_switch = 0
        switch_count = 1
        i = 1
        j = 1
        Topo.__init__(self)
        
        #for server in ft_topo.servers:
           # info('*** ft_topo Server - ', server.id,' ***\n')
        #for switch in ft_topo.switches:
            #info('*** ft_topo Switch - ', switch.id,' ***\n')

        for switch in ft_topo.switches :

            if "c-" in switch.id :
                dp_id = "00:00:00:00:00:" + str(hex(switch_count))
                switch_count += 1
                added_switch = self.addSwitch(switch.id, 
                cls = OVSKernelSwitch, 
                ip = '10.'+str(num_ports)+'.'+str(i)+'.'+str(j),
                dpid = dp_id)
                self.name_dpId_map[dp_id] = switch.id
                print("\n Switch name - ",switch.id , " Switch dp id - ",dp_id)
                core_switch += 1
                self.node_map[switch.id] = added_switch
                j += 1
                if j >= half_ports :
                    i += 1
                    j = 1

            elif "a-" in switch.id :
                dp_id = "00:00:00:00:00:" + str(hex(switch_count))
                switch_count += 1
                added_switch = self.addSwitch(switch.id, 
                cls = OVSKernelSwitch, 
                ip = '10.'+str(pod_count)+'.'+str(aggr_count)+'.'+"1",
                dpid = dp_id)
                self.name_dpId_map[dp_id] = switch.id
                print("\n Switch name - ",switch.id , " Switch dp id - ",dp_id)
                aggr_switch += 1
                self.node_map[switch.id] = added_switch
                aggr_count += 1
                if aggr_count >= num_ports :
                    pod_count += 1
                    aggr_count = half_ports
                if pod_count >= num_ports :
                    pod_count = 0

            else : 
                dp_id = "00:00:00:00:00:" + str(hex(switch_count))
                switch_count += 1
                added_switch = self.addSwitch(switch.id, 
                cls = OVSKernelSwitch, 
                ip = '10.'+str(pod_count)+'.'+str(edge_count)+'.'+"1",
                dpid = dp_id)
                self.name_dpId_map[dp_id] = switch.id
                edge_switch += 1
                self.node_map[switch.id] = added_switch
                print("\n Switch name - ",switch.id , " Switch dp id - ",dp_id)
                edge_count += 1
                if edge_count >= half_ports :
                    pod_count += 1
                    edge_count = 0
                if pod_count >= num_ports :
                    pod_count = 0

        pod_count = 0
        edge_count = 0
        host_count = 2

        for host in ft_topo.servers :
            dp_id = str(4) + str(server_count)
            info("\n Host - ",dp_id)
            added_host = self.addHost(host.id,
            ip = '10.'+str(pod_count)+'.'+str(edge_count)+'.'+ str(host_count),
            dpid = dp_id)
            self.name_dpId_map[dp_id] = host.id
            server_count += 1
            self.node_map[host.id] = added_host 
            print("\n Hose name - ",host.id , " Host dp id - ",dp_id)
            host_count += 1
            if host_count - 2 >= half_ports:
                edge_count += 1
                host_count = 2
            if edge_count >= half_ports :
                pod_count += 1
                edge_count = 0 

        for switch in ft_topo.switches :
            for edge in switch.edges :
                r_neighbour_node = edge.rnode
                l_neighbour_node = edge.lnode

                if str(switch.id)+"-"+str(r_neighbour_node.id) not in links and str(r_neighbour_node.id)+"-"+str(switch.id) not in links and switch.id != r_neighbour_node.id:
                    info("neighbour node id -"+r_neighbour_node.id + "Switch id- "+switch.id)
                    self.addLink(self.node_map[switch.id],self.node_map[r_neighbour_node.id], bw=15, delay='10ms', cls = TCLink)
                    links.add(str(switch.id)+"-"+str(r_neighbour_node.id))

                if str(switch.id)+"-"+str(l_neighbour_node.id) not in links and str(l_neighbour_node.id)+"-"+str(switch.id) not in links and switch.id != l_neighbour_node.id:
                    info("neighbour node id -"+l_neighbour_node.id + "Switch id- "+switch.id)
                    self.addLink(self.node_map[switch.id],self.node_map[l_neighbour_node.id], bw=15, delay='10ms', cls = TCLink)
                    links.add(str(switch.id)+"-"+str(l_neighbour_node.id))

"""
        for i in range(1, half_ports + 1):
            for j in range(1, half_ports + 1):
                switch = self.addSwitch("core"+str(core_count), cls = OVSKernelSwitch, ip = '10.'+str(num_ports)+'.'+str(i)+'.'+str(j), dpid = "core"+str(core_count))
                self.core_switches.append(switch)
                core_count +=1

        core_count=0

        for i in range (int((num_ports**2)/2)):
            switch = self.addSwitch("aggr"+str(pod_count)+str(aggr_count), cls = OVSKernelSwitch, ip = '10.'+str(pod_count)+'.'+str(aggr_count)+'.1')
            self.aggr_switches.append(switch)
            aggr_count +=1
            for j in range(half_ports):
                link = self.addLink(switch, self.core_switches[core_count +j], bw= 15, delay='15ms', cls = TCLink)
            self.all_links.append(link)
            core_count += half_ports
            if aggr_count >= num_ports:
                pod_count += 1
                aggr_count = half_ports
                core_count =0

        pod_count = 0
        aggr_count = 0

        for i in range (int((num_ports**2)/2)):
            switch = self.addSwitch("edge"+str(pod_count)+str(edge_count), cls = OVSKernelSwitch, ip = '10.'+str(pod_count)+'.'+str(edge_count)+'.1')
            self.edge_switches.append(switch)
            for j in range(half_ports):
                link = self.addLink(switch, self.aggr_switches[aggr_count +j], bw= 15, delay='15ms', cls = TCLink)
                self.all_links.append(link)
            for k in range (2, half_ports + 2):
                server = self.addHost('host'+str(server_count), ip = '10.'+str(pod_count)+'.'+str(edge_count)+'.'+ str(k))
                server_count +=1
                link = self.addLink(server,switch, bw=15, delay='10ms', cls = TCLink)
                self.all_links.append(link)
                self.servers.append(server)
            edge_count +=1
            if edge_count >= half_ports:
                pod_count += 1
                aggr_count += half_ports
                edge_count =0

        info('*** Printing Hosts ***\n')
        for host in self.servers:
            info('Server name - '+host+ '\n')
        info('*** Printing Core Switches ***\n')
        for switch in self.core_switches:
            info('Switch name - '+switch+ '\n')
        info('*** Printing Aggr Switches ***\n')
        for switch in self.aggr_switches:
            info('Switch name - '+switch+ '\n')
        info('*** Printing Edge Switches ***\n')
        for switch in self.edge_switches:
            info('Switch name - '+switch+ '\n')
        info('*** Printing Links ***\n')
        for link in self.all_links:
            info('Link - '+str(link)+'\n')

"""

def make_mininet_instance(graph_topo):

    net_topo = FattreeNet(graph_topo)
    net = Mininet(topo=net_topo, controller=None, autoSetMacs=True)
    net.addController('c0', controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    return net


def run(graph_topo):

    # Run the Mininet CLI with a given topology
    lg.setLogLevel('info')
    mininet.clean.cleanup()
    net = make_mininet_instance(graph_topo)

    info('*** Starting network ***\n')
    net.start()
    info('*** Running CLI ***\n')
    CLI(net)
    info('*** Stopping network ***\n')
    net.stop()


if __name__ == '__main__':
    ft_topo = Fattree(num_ports)
    run(ft_topo)
