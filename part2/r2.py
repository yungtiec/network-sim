"""

    EE 555 Project - Router Exercise

        PART II

    Name:   Hao Zhang
    Email:  zhan849@usc.edu
    USC ID: 5211-2727-12

    To Run:
    $ ./pox.py log.level --DEBUG misc.router_part2 misc.full_payload

    ARP support:
        * arp cache
        * routing table (create a structure with all of the information statically assigned)
        * ip to port dictionary
        * message queue (while the router waits for an ARP reply)

    Static Routing:
        * We need to handle all ipv4 traffic that comes through the router by forwarding it to the correct subnet. 
        * The only change in the packet should be the source and destination MAC addresses.

    ICMP:
        * controller may receive ICMP echo (ping) requests for the router, which it should respond to
        * packets for unreachable subnets should be responded to with ICMP network unreachable messages
        
"""


from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.revent import *

import struct
import time

log = core.getLogger()

DEFAULT_GATEWAY = 1

def dpid_to_mac(dpid):
    # generate dummy MAC for switch
    return EthAddr("%012x" % (dpid & 0xffffffffffff | 0x0000000000f0,))

def dpid_to_ip(dpid):
    return IPAddr('10.0.%d.1' % (dpid) )

def is_same_subnet(ip1, ip2):
    str1 = str(ip1)
    str2 = str(ip2)
    (a,b,c,d) = str1.split('.')
    (e,f,g,h) = str2.split('.')
    if a==e and b==f and c==g:
        return True
    else:
        return False

class Router (EventMixin):
    def __init__ (self):
        log.debug('router registered')
        self.validIP = set([IPAddr('10.0.1.1'), IPAddr('10.0.1.2'), IPAddr('10.0.1.3'), IPAddr('10.0.2.1'), 
                IPAddr('10.0.2.2'), IPAddr('10.0.2.3'), IPAddr('10.0.2.4')])

        # each dpid has its own arp table
        # arp[ip] = ethaddr
        self.arpTable = {}

        # each dpid has its own routing table
        # rt[ip] = port
        self.routingTable = {}

        # store connections
        # connection to data path
        self.connections = {}

        # for those waiting for ARP response
        # each dpid has its own ARP waiting list
        # for each dpid, [ip] => list of (buffer_id, inport) turple
        self.arpWait = {}
        
        # dpid => router ip
        self.routerIP = {}

        self.listenTo(core)
        


    def _resend_packet (self, dpid, packet_in, out_port):
        """
        Instructs the switch to resend a packet that it had sent to us.
        "packet_in" is the ofp_packet_in object the switch had sent to the
        controller due to a table-miss.
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in

        # Add an action to send to the specified port
        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connections[dpid].send(msg)


    def _handle_GoingUpEvent (self, event):
        self.listenTo(core.openflow)
        log.debug("Router is UP..." )

    def _handle_ConnectionUp(self, event):
        log.debug("DPID %d is UP..." % event.dpid)
        self._learn_from_ConnectionUp(event)

    def _handle_ConnectionDown(self, event):
        log.debug("DPID %d is DOWN, cleaning dp cache" % event.dpid)
        if event.dpid in self.arpTable:
            del self.arpTable[event.dpid]

        if event.dpid in self.routingTable:
            del self.routingTable[event.dpid]

        if event.dpid in self.connections:
            del self.connections[event.dpid]
        
        if event.dpid in self.arpWait:
            del self.arpWait[event.dpid]

        if event.dpid in self.routerIP:
            del self.routerIP[event.dpid]

    def _learn_from_ConnectionUp(self, event):
        dpid = event.dpid
        myip = dpid_to_ip( dpid )
        mymac = dpid_to_mac( dpid )
        conn = event.connection
        self.routerIP[event.dpid] = myip

        if dpid not in self.connections:
            self.connections[dpid] = conn

        if dpid not in self.arpTable:
            self.arpTable[dpid] = {}

        if dpid not in self.routingTable:
            self.routingTable[dpid] = {}

        if dpid not in self.arpWait:
            self.arpWait[dpid] = {}

        self.arpTable[event.dpid][myip] = mymac
        if len(self.routerIP) == 2:
            self._generate_arp_request(myip, dpid_to_ip(3-event.dpid), mymac, of.OFPP_FLOOD, dpid)

    def _process_arp_packet(self, a, inport, dpid, packet_in):
        log.debug("DPID %d: ARP packet, INPORT %d,  ARP %s %s => %s", dpid, inport,
                {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode, 'op:%i' % (a.opcode,)),
                str(a.protosrc), str(a.protodst))


        if a.prototype == arp.PROTO_TYPE_IP:
            if a.hwtype == arp.HW_TYPE_ETHERNET:
                if a.protosrc != 0:
                    # learn the MAC
                    if a.protosrc not in self.arpTable[dpid]:
                        self.arpTable[dpid][a.protosrc] = a.hwsrc
                        log.debug('DPID %d: added arpTable entry: ip = %s, mac = %s' % (dpid, str(a.protosrc), str(a.hwsrc)))
                        #print self.arpWait[dpid]
                        if a.protosrc in self.arpWait[dpid] and len(self.arpWait[dpid][a.protosrc]) != 0:
                            self._process_arp_wait(dpid, a.protosrc)

                    if a.opcode == arp.REQUEST:
                        if str(a.protodst) == str(self.routerIP[dpid]):
                            self._generate_arp_response(a, inport, dpid)
                        else:
                            self._resend_packet(dpid, packet_in, of.OFPP_FLOOD)
                    elif a.opcode == arp.REPLY and a.protodst != dpid_to_ip(dpid):
                        # ARP request not to this router
                        self._resend_packet(dpid, packet_in, self.routingTable[dpid][a.protodst])
                            
        else:
            log.debug("DPID %d: Unknow ARP request, flooding" % (dpid))
            self._resend_packet (dpid, packet_in, of.OFPP_FLOOD)


    def _process_arp_wait(self, dpid, ip):
        log.debug('DPID %d: processing pending arpWait packet for ip %s' % (dpid, str(ip)))
        while len(self.arpWait[dpid][ip]) > 0:
            (bid, inport) = self.arpWait[dpid][ip][0]
            msg = of.ofp_packet_out(buffer_id=bid, in_port=inport)
            msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arpTable[dpid][ip]))
            msg.actions.append(of.ofp_action_output(port = self.routingTable[dpid][ip]))
            self.connections[dpid].send(msg)
            log.debug("DPID %d: sending arp wait packet, buffer id: %d, destip: %s, destmac: %s, output port: %d" % (dpid, bid, str(ip), str(self.arpTable[dpid][ip]), self.routingTable[dpid][ip]))
            del self.arpWait[dpid][ip][0]

    def _generate_arp_response(self, a, inport, dpid):
        r = arp()
        r.hwtype = a.hwtype
        r.prototype = a.prototype
        r.hwlen = a.hwlen
        r.protolen = a.protolen
        r.opcode = arp.REPLY
        r.hwdst = a.hwsrc
        r.protodst = a.protosrc
        r.protosrc = a.protodst
        r.hwsrc = self.arpTable[dpid][a.protodst]
        
        e = ethernet(type=ethernet.ARP_TYPE, src=self.arpTable[dpid][a.protodst], dst=a.hwsrc)
        e.set_payload(r)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.in_port = inport

        log.debug("DPID %d, INPORT %d, answering for arp from %s: MAC for %s is %s", dpid, inport, str(a.protosrc), str(r.protosrc), str(r.hwsrc))
        self.connections[dpid].send(msg)


    def _generate_arp_request(self, srcip, dstip, srcmac, inport, dpid):
        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.hwlen = 6
        r.protolen = r.protolen
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = dstip                  # only thing that matters
        r.hwsrc = srcmac                    # really doesn't matter in this case
        r.protosrc = srcip                  # also, really doesn't matter in this case
        e = ethernet(type=ethernet.ARP_TYPE, src=srcmac,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        log.debug("DPID %i, INPORT %i, sending ARP Request for %s on behalf of %s" % (dpid, inport, str(r.protodst), str(r.protosrc)))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connections[dpid].send(msg)

    def _generate_icmp_reply(self, dpid, p, srcip, dstip, icmp_type):
        p_icmp = icmp()
        p_icmp.type = icmp_type
        if icmp_type == pkt.TYPE_ECHO_REPLY:
            p_icmp.payload = p.find('icmp').payload
        elif icmp_type == pkt.TYPE_DEST_UNREACH:
            #print dir(p.next)
            orig_ip = p.find('ipv4')
            d = orig_ip.pack()
            d = d[:orig_ip.hl * 4 + 8]
            d = struct.pack("!HH", 0, 0) + d # network, unsigned short, unsigned short
            p_icmp.payload = d

        
        p_ip = ipv4()
        p_ip.protocol = p_ip.ICMP_PROTOCOL
        p_ip.srcip = dstip  # srcip, dstip in the argument is from the ping
        p_ip.dstip = srcip
        

        e = ethernet()
        e.src = p.dst
        if is_same_subnet(srcip, self.routerIP[dpid]):
            e.dst = p.src
        else:
            gatewayip = dpid_to_ip( 3-dpid )
            e.dst = self.arpTable[dpid][gatewayip]

        e.type = e.IP_TYPE
        
        p_ip.payload = p_icmp
        e.payload = p_ip
        
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.data = e.pack()
        msg.in_port = self.routingTable[dpid][srcip]
        self.connections[dpid].send(msg)
        log.debug('DPID %d: IP %s pings router at %s, generating icmp reply with code %d...', dpid, str(srcip), str(dstip), icmp_type)


    def _learn_route(self, ip, dpid, inport):
        if ip not in self.routingTable[dpid]:
            log.debug('DPID %d: Added IP %s into routing Table, output port %d' % (dpid, str(ip), inport))
            self.routingTable[dpid][ip] = inport
        else:
            log.debug('DPID %d: IP %s is in routing Table, RE_LEARNED, output port %d' % (dpid, str(ip), inport) )
    
    def _add_route_ipv4_flow_mod(self, dstip, nextHopMac, out_port, dpid):
        msg = of.ofp_flow_mod()
        msg.idle_timeout = 3600
        msg.hard_timeout = 7200
        msg.priority = 1000
        msg.match.dl_type = 0x800 # ip packet
        msg.match.nw_dst = dstip
        msg.actions.append( of.ofp_action_dl_addr.set_dst(nextHopMac) )
        msg.actions.append( of.ofp_action_output(port = out_port) )
        self.connections[dpid].send(msg)

    
    def _validate_ip(self, ip):
        return ip in self.validIP

    def _handle_PacketIn (self, event):
        packet = event.parsed # This is the parsed packet data.
        dpid = event.connection.dpid
        inport = event.port

        # error checking and sanitation
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        
        if packet.type == ethernet.LLDP_TYPE:
            # Ignore LLDP packets
            log.debug('Ignoring LLDP packet')
            return


        packet_in = event.ofp # The actual ofp_packet_in message.
        n = packet.next

        # deal with different packets
        if isinstance(n, ipv4):
            log.debug('DPID %d: IPv4 Packet, INPORT %d, IP %s => %s', dpid, inport, packet.next.srcip, packet.next.dstip)
            # learn the route
            self._learn_route(n.srcip, dpid, inport)
            if not self._validate_ip(n.dstip):
                self._generate_icmp_reply(dpid, packet, n.srcip, n.dstip, pkt.TYPE_DEST_UNREACH)
                return

            if str(n.dstip) == str(self.routerIP[dpid]):
                if isinstance(n.next, icmp):
                    log.debug("DPID %d: ICMP packet to this router" % dpid )
                    if n.next.type == pkt.TYPE_ECHO_REQUEST:
                        # generate ICMP echo reply
                        self._generate_icmp_reply(dpid, packet, n.srcip, n.dstip, pkt.TYPE_ECHO_REPLY)
            elif not is_same_subnet(n.dstip, self.routerIP[dpid]):
                # not in the same subnet, forward to next hop router and inject a flow mod
                nextHopIP = IPAddr('10.0.%d.1' % (3-dpid))
                nextHopMac = self.arpTable[dpid][nextHopIP]
                msg = of.ofp_packet_out( buffer_id=packet_in.buffer_id, in_port=inport )
                msg.actions.append(of.ofp_action_dl_addr.set_dst( nextHopMac ))
                msg.actions.append(of.ofp_action_output( port = 1 ))
                self.connections[dpid].send(msg)
                log.debug('DPID %d, packet %s => %s, different subnet, sent to port %d', dpid, str(n.srcip), str(n.dstip), 1)

                self._add_route_ipv4_flow_mod(n.dstip, nextHopMac, 1, dpid)
            else:
                # in the same subnet
                if n.dstip not in self.routingTable[dpid] or n.dstip not in self.arpTable[dpid]:
                    if n.dstip not in self.arpWait[dpid]:
                        self.arpWait[dpid][n.dstip] = []
                    entry = (packet_in.buffer_id, inport)
                    self.arpWait[dpid][n.dstip].append(entry)
                    log.debug('DPID %d, packet %s => %s, buffer_id %d, destination unknown, added to arpWait, prepare arp request' % (dpid, str(n.srcip), str(n.dstip), packet_in.buffer_id))
                    # _generate_arp_request(self, srcip, dstip, srcmac, inport, dpid)
                    self._generate_arp_request(n.srcip, n.dstip, packet.src, inport, dpid)
                else:
                    msg = of.ofp_packet_out(buffer_id=packet_in.buffer_id, in_port=inport)
                    msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arpTable[dpid][n.dstip]))
                    msg.actions.append(of.ofp_action_output(port = self.routingTable[dpid][n.dstip]))
                    self.connections[dpid].send(msg)
                    log.debug('DPID %d, packet %s => %s, same subnet, sent to port %d', dpid, str(n.srcip), str(n.dstip), self.routingTable[dpid][n.dstip])

                    self._add_route_ipv4_flow_mod(n.dstip, self.arpTable[dpid][n.dstip], self.routingTable[dpid][n.dstip], dpid)

        elif isinstance(n, arp):
            self._learn_route(n.protosrc, dpid, inport)
            self._process_arp_packet(n, inport, dpid, packet_in)


            


def launch():
    core.registerNew(Router)
