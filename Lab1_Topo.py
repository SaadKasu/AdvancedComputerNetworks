# Python Script For Structure Lab 1

from mininet.topo import Topo
from mininet.node import OVSBridge
from mininet.link import TCLink

class BridgeTopo(Topo):
    def __init__(self):

        Topo.__init__(self)

#net = Mininet(link=TCLink, switch=OVSBridge)

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        ser = self.addHost('ser')
        ext = self.addHost('ext')

        s1 = self.addSwitch('s1', cls = OVSBridge)
        s2 = self.addSwitch('s2', cls = OVSBridge)
        s3 = self.addSwitch('s3', cls = OVSBridge)

        l1 = self.addLink(h1,s1, bw=15, delay='10ms', cls = TCLink)
        l2 = self.addLink(h2,s1, bw=15, delay='10ms', cls = TCLink)
        l3 = self.addLink(s3,s1, bw=15, delay='10ms', cls = TCLink)
        l4 = self.addLink(ser,s2, bw=15, delay='10ms', cls = TCLink)
        l5 = self.addLink(s3,s2, bw=15, delay='10ms', cls = TCLink)
        l6 = self.addLink(s3,ext, bw=15, delay='10ms', cls = TCLink)


topos = {'bridge': (lambda: BridgeTopo())}
