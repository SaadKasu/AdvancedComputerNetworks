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

import os
import subprocess
import time

# Class for an edge in the graph
class Edge:
	def __init__(self):
		self.lnode = None
		self.rnode = None
	
	def remove(self):
		self.lnode.edges.remove(self)
		self.rnode.edges.remove(self)
		self.lnode = None
		self.rnode = None

# Class for a node in the graph
class Node:
	def __init__(self, id, type):
		self.edges = []
		self.id = id
		self.type = type

	# Add an edge connected to another node
	def add_edge(self, node):
		edge = Edge()
		edge.lnode = self
		edge.rnode = node
		self.edges.append(edge)
		node.edges.append(edge)
		return edge

	# Remove an edge from the node
	def remove_edge(self, edge):
		self.edges.remove(edge)

	# Decide if another node is a neighbor
	def is_neighbor(self, node):
		for edge in self.edges:
			if edge.lnode == node or edge.rnode == node:
				return True
		return False


class Fattree:

    def __init__(self, num_ports):
        self.servers = []
        self.switches = []
        self.generate(num_ports)

    def generate(self, num_ports):
        half_ports = int(num_ports/2)
        number_core_switches = int(half_ports**2)
        half_switches_in_pod = int((num_ports**2)/2)
        number_hosts = int((num_ports**3)/4)
        # Core Layer Switch Creation
        for switch_number in range(number_core_switches):
            currNode = Node("core"+str(switch_number), "switch")
            self.switches.append(currNode)
        # Aggregation Layer Switch Creation
        count = 0 
        for switch_number in range(half_switches_in_pod):
            currNode = Node("aggregation"+str(switch_number), "switch")
            self.switches.append(currNode)
            for core_switch_number in range(count, count + half_ports):
                currNode.add_edge(self.switches[core_switch_number])
            count += half_ports
            if count >=number_core_switches :
                count = 0

        # Edge Layer Switch Creation
        count = number_core_switches
        count_edge_switches = 0
        for switch_number in range(half_switches_in_pod):
            currNode = Node("edge"+str(switch_number), "switch")
            self.switches.append(currNode)
            count_edge_switches+=1
            for aggr_switch_number in range(count, count + half_ports):
                currNode.add_edge(self.switches[aggr_switch_number])
            if count_edge_switches >= half_ports:
                count_edge_switches = 0
                count += half_ports

        # Host Creation 
        count = number_core_switches + half_switches_in_pod
        hosts_in_switch = 0
        for server_number in range(number_hosts):
            currNode = Node("host"+str(server_number), "host")
            self.servers.append(currNode)
            hosts_in_switch+=1
            currNode.add_edge(self.switches[count])
            if hosts_in_switch >= half_ports:
                hosts_in_switch = 0
                count+=1
		
        # Checking the Degree of each switch in the topology.
        print ('Printing degree of each switch in topology')
        for node in self.switches: 
            print('*** Degree of Switch ',node.id, ' is - ', len(node.edges), '\n')


        # Checking the Degree of each host in the topology.
        print ('Printing degree of each server in topology')
        for node in self.servers:
            print('*** Degree of Server ',node.id, ' is - ', len(node.edges), '\n')

        print ('Checking the neigbours of each Node')
        for first_node in self.switches:
            for second_node in self.switches:
                if first_node.is_neighbor(second_node) and first_node.id != second_node.id:
                    print(first_node.id,'-is neighbour of-',second_node.id,'\n')

            for second_node in self.servers:
                if first_node.is_neighbor(second_node) and first_node.id != second_node.id:
                    print(first_node.id,'-is neighbour of-',second_node.id,'\n')
