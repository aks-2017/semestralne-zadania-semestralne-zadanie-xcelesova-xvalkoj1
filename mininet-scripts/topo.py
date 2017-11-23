from mininet.topo import Topo

class DoviTopo( Topo ):

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
	h1 = self.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1/24')
	h2 = self.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2/24')
	h3 = self.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3/24')
	h4 = self.addHost('h4', mac='00:00:00:00:00:04', ip='10.0.0.4/24')
	h5 = self.addHost('h5', mac='00:00:00:00:00:05', ip='10.0.0.5/24')
	h6 = self.addHost('h6', mac='00:00:00:00:00:06', ip='10.0.0.6/24')
	
	s1 = self.addSwitch('s1')
	s2 = self.addSwitch('s2')
	s3 = self.addSwitch('s3')
	s4 = self.addSwitch('s4')
	s5 = self.addSwitch('s5')
	s6 = self.addSwitch('s6')
	s7 = self.addSwitch('s7')
	s8 = self.addSwitch('s8')
	s9 = self.addSwitch('s9')
	s10 = self.addSwitch('s10')

        # Add links
        self.addLink(h1, s3)
        self.addLink(h2, s4)
        self.addLink(s3, s4)
        #self.addLink(s1, s4)
        #self.addLink(s2, s3)
        self.addLink(s1, s2)
        self.addLink(s2, s5)
        self.addLink(s4, s5)
        
	self.addLink(s5, s6)

	self.addLink(s6, s7)
        self.addLink(s6, s9)
        self.addLink(s7, s8)
        #self.addLink(s7, s10)
        #self.addLink(s8, s9)
        self.addLink(s9, s10)
        self.addLink(h3, s9)
        self.addLink(h4, s10)

	self.addLink(h5, s1)
        self.addLink(h6, s2)

topos = { 'dovitopo': ( lambda: DoviTopo() ) }
