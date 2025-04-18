# Python Script For Lab 0
#!/usr/bin/python
from mininet.topo import Topo

class BridgeTopo(Topo):
    def __init__(self):

        Topo.__init__(self)

#net = Mininet(link=TCLink, switch=OVSBridge)

        h1 = self.addHost(h1)
        h2 = self.addHost(h2)
        h3 = self.addHost(h3)
        h4 = self.addHost(h4)

        s1 = self.addSwitch(s1)
        s2 = self.addSwitch(s2)

        l1 = self.addLink(s1,s2, bw=20, delay='45ms')
        l2 = self.addLink(h1,s1, bw=15, delay='10ms')
        l3 = self.addLink(h2,s1, bw=15, delay='10ms')
        l4 = self.addLink(h3,s2, bw=15, delay='10ms')
        l5 = self.addLink(h4,s2, bw=15, delay='10ms')

