# Python Script For Structure Lab 1

from mininet.topo import Topo

class BridgeTopo(Topo):
     def __init__(self):

        Topo.__init__(self)

net = Mininet(link=TCLink, switch=OVSBridge)

h1 = net.addHost(h1)
h2 = net.addHost(h2)
ser = net.addHost(ser)
ext = net.addHost(ext)

s1 = net.addSwitch(s1)
s2 = net.addSwitch(s2)
s3 = net.addSwitch(s3)

l1 = addLink(s1,s3, bw=15, delay='10ms')
l2 = addLink(s3,s2, bw=15, delay='10ms')
l3 = addLink(h1,s1, bw=15, delay='10ms')
l4 = addLink(h2,s1, bw=15, delay='10ms')
l5 = addLink(ser,s2, bw=15, delay='10ms')
l6 = addLink(ext,s3, bw=15, delay='10ms')

