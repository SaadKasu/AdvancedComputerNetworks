# Python Script For Lab 0

from mininet.topo import Topo

net = Mininet(link=TCLink, switch=OVSBridge)

h1 = net.addHost(h1)
h2 = net.addHost(h2)
h3 = net.addHost(h3)
h4 = net.addHost(h4)

s1 = net.addSwitch(s1)
s2 = net.addSwitch(s2)

l1 = addLink(s1,s2, bw=20, delay='45ms')
l2 = addLink(h1,s1, bw=15, delay='10ms')
l3 = addLink(h2,s1, bw=15, delay='10ms')
l4 = addLink(h3,s2, bw=15, delay='10ms')
l5 = addLink(h4,s2, bw=15, delay='10ms')

