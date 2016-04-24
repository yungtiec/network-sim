"""
Router Exercise Topology

https://github.com/mininet/openflow-tutorial/wiki/Router-Exercise

                                host5(h5)
                                  | 
   host1(h1) -- switch(s1) -- switch(s2) -- host3(h3)
                   |              |
                host2(h2)       host4(h4)

$ sudo mn --custom ~/mininet/mytopo2.py --topo mytopo --mac --controller=remote,ip=127.0.0.1

"""

from mininet.topo import Topo

class MyTopo( Topo ):

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        host1 = self.addHost( 'h1', ip='10.0.1.2/24', defaultRoute = 'via 10.0.1.1' )
        host2 = self.addHost( 'h2', ip='10.0.1.3/24', defaultRoute = 'via 10.0.1.1' )
        host3 = self.addHost( 'h3', ip='10.0.2.2/24', defaultRoute = 'via 10.0.2.1' )
        host4 = self.addHost( 'h4', ip='10.0.2.3/24', defaultRoute = 'via 10.0.2.1' )
        host5 = self.addHost( 'h5', ip='10.0.2.4/24', defaultRoute = 'via 10.0.2.1' )

        # Add hosts and switches
        switch1 = self.addSwitch( 's1' )
        switch2 = self.addSwitch( 's2' )

        # Add links
        self.addLink( 's1', 's2', port1=1, port2=1 )
        self.addLink( 'h1', 's1', port1=1, port2=2 )
        self.addLink( 'h2', 's1', port1=1, port2=3 )
        self.addLink( 'h3', 's2', port1=1, port2=2 )
        self.addLink( 'h4', 's2', port1=1, port2=3 )
        self.addLink( 'h5', 's2', port1=1, port2=4 )


topos = { 'mytopo': ( lambda: MyTopo() ) }