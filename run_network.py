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

#!/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

class NetworkTopo(Topo):

    def build(self):  # ⬅ use build() instead of __init__ for modern Topo subclasses
        # Hosts
        h1 = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
        ser = self.addHost('ser', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
        ext = self.addHost('ext', ip='192.168.1.123/24', defaultRoute='via 192.168.1.1')

        # Switches
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch)
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch)
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch, dpid='0000000000000003')  # OF 1.3 needs 16-digit hex

        # Links
        self.addLink(h1, s1, bw=15, delay='10ms', cls=TCLink)
        self.addLink(h2, s1, bw=15, delay='10ms', cls=TCLink)

        # Connect s3 to s1 with MAC on s3 side
        self.addLink(s3, s1, bw=15, delay='10ms', cls=TCLink,
                     intfName1='s3-eth1', params1={'mac': '00:00:00:00:01:01'})

        self.addLink(ser, s2, bw=15, delay='10ms', cls=TCLink)

        # Connect s3 to s2 with MAC on s3 side
        self.addLink(s3, s2, bw=15, delay='10ms', cls=TCLink,
                     intfName1='s3-eth2', params1={'mac': '00:00:00:00:01:02'})

        # Connect s3 to ext host with MAC on s3 side
        self.addLink(s3, ext, bw=15, delay='10ms', cls=TCLink,
                     intfName1='s3-eth3', params1={'mac': '00:00:00:00:01:03'})

def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo,
                  controller=None,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  autoSetMacs=False)

    net.addController('c1', controller=RemoteController, ip="127.0.0.1", port=6653)
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
