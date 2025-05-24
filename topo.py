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
        half_ports = num_ports/2
        number_core_switches = half_ports**2
        half_switches_in_pod = (num_ports**2)/2
        number_hosts = (num_ports**3)/4
        # Core Layer Switch Creation
        for switch_number in range(number_core_switches):
            currNode = Node("core-"+str(switch_number), "switch")
            switches.add(currNode)
        # Aggregation Layer Switch Creation
        count = 0 
        for switch_number in range(half_switches_in_pod):
            currNode = Node("aggregation-"+str(switch_number), "switch")
            switches.add(currNode)
            for core_switch_number in range(count, count + num_ports/2):
                currNode.add_edge(switches[core_switch_number])
            count += num_ports/2
            if count >=number_core_switches :
                count = 0

        # Edge Layer Switch Creation
        count = number_core_switches
        count_edge_switches = 0
        for switch_number in range(half_switches_in_pod):
            currNode = Node("edge-"+str(switch_number), "switch")
            switches.add(currNode)
            count_edge_switches++
            for aggr_switch_number in range(count, count + num_ports/2):
                currNode.add_edge(switches[aggr_switch_number])
            if count_edge_switches >= num_ports/2:
                count_edge_switches = 0
                count += num_ports/2

        # Host Creation 
        count = number_core_switches + half_switches_in_pod
        hosts_in_server = 0
        for server_number in range(number_hosts):
            currNode = Node("host-"+str(server_number), "host")
            servers.add(currNode)
            hosts_in_switch++
            currNode.add_edge(switches[count])
            if hosts_in_switch >= num_ports/2:
                hosts_in_switch = 0
                count++
		
        # Checking the Degree of each switch in the topology.
        info ('Printing degree of each switch in topology')
        for node in switches    
            info('*** Degree of Switch ',node.id, ' is - ', len(node.edges), '\n')


        # Checking the Degree of each host in the topology.
        info ('Printing degree of each server in topology')
        for node in servers    
            info('*** Degree of Server ',node.id, ' is - ', len(node.edges), '\n')
