#!/usr/bin/python

import os
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info, debug
from mininet.node import Host, RemoteController

class MyTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        #add hosts
        #h1 = self.addHost('h1',ip='192.168.1.100/24')
        #h2 = self.addHost('h2',ip='192.168.2.100/24')
        
        h1 = self.addHost('h1',ip='192.168.1.100/24',defaultRoute='via 192.168.1.254')

        h2 = self.addHost('h2',ip='192.168.2.100/24',defaultRoute='via 192.168.2.254')

        #add switch 
        s1 = self.addSwitch('s1',failMode ='standalone')

        #add routers
        r1 = self.addHost('r1')
        r2 = self.addHost('r2')

        #add links
        self.addLink(r1, s1)
        self.addLink(r2, s1)

        self.addLink(r1, h1)
        self.addLink(r2, h2)


#topos = { CLI : Class }
topos = { 'mytopo' : MyTopo }

if __name__ == '__main__':

    setLogLevel('info')
    # ( 'info' | 'debug' | 'output' )
    topo = MyTopo()
    net = Mininet(topo=topo,controller=None)

    # h1 = net.get('h1')
    # h1.cmd('ip route add default via 192.168.1.254')
    # h2 = net.get('h2')
    # h2.cmd('ip route add default via 192.168.2.254')
    r1 = net.get('r1')
    r1.cmd('ifconfig r1-eth1 192.168.1.254 broadcast 192.168.1.255 netmask 255.255.255.0')
    r1.cmd('sysctl -w net.ipv4.ip_forward=1')
    r2 = net.get('r2')
    r2.cmd('ifconfig r2-eth1 192.168.2.254 broadcast 192.168.2.255 netmask 255.255.255.0')
    r2.cmd('sysctl -w net.ipv4.ip_forward=1')

    r1.cmd('zebra -f ./zebra.conf -d -i /var/run/quagga/zebraR1.pid')
    r1.cmd('bgpd -f ./bgp_r1.conf -d -i /var/run/quagga/bgpdR1.pid')
    r2.cmd('zebra -f ./zebra.conf -d -i /var/run/quagga/zebraR2.pid')
    r2.cmd('bgpd -f ./bgp_r2.conf -d -i /var/run/quagga/bgpdR2.pid')

    net.start()
    CLI(net)
    net.stop()

    os.system("sudo kill -9 `cat /var/run/quagga/bgpdR1.pid`")
    os.system("sudo kill -9 `cat /var/run/quagga/bgpdR2.pid`")
    os.system("sudo kill -9 `cat /var/run/quagga/zebraR1.pid`")
    os.system("sudo kill -9 `cat /var/run/quagga/zebraR2.pid`")
    info("done\n")
