"""
    EE 555 Project - Router Exercise

        PART I

    Name:   Hao Zhang
    Email:  zhan849@usc.edu
    USC ID: 5211-2727-12

    To run:
    $ ./pox.py log.level --DEBUG misc.router misc.full_payload        

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

log = core.getLogger()

def dpid_to_mac (dpid):
    # generate dummy MAC for switch
    return EthAddr("%012x" % (dpid & 0xffffffffffff | 0x0000000000f0,))

class Router (EventMixin):
    def __init__ (self, fakeways = []):
        log.debug('router registered')
        self.fakeways = fakeways

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


    def _process_arp_packet(self, a, inport, dpid, packet_in):
        log.debug("115 DPID %d: ARP packet, INPORT %d,  ARP %s %s => %s", dpid, inport,
                {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode, 'op:%i' % (a.opcode,)),
                str(a.protosrc), str(a.protodst))


        if a.prototype == arp.PROTO_TYPE_IP:
            if a.hwtype == arp.HW_TYPE_ETHERNET:
                if a.protosrc != 0:
                    # learn the MAC
                    if a.protosrc not in self.arpTable[dpid]:
                        self.arpTable[dpid][a.protosrc] = a.hwsrc
                        log.debug('126 DPID %d: added arpTable entry: ip = %s, mac = %s' % (dpid, str(a.protosrc), str(a.hwsrc)))
                        #print self.arpWait[dpid]
                        if a.protosrc in self.arpWait[dpid] and len(self.arpWait[dpid][a.protosrc]) != 0:
                            self._process_arp_wait(dpid, a.protosrc)

                    if a.opcode == arp.REQUEST and a.protodst in self.fakeways:
                        self._generate_arp_response(a, inport, dpid)
        else:
            log.debug("134 DPID %d: Unknow ARP request, flooding" % (dpid))
            self._resend_packet (dpid, packet_in, of.OFPP_FLOOD)


    def _process_arp_wait(self, dpid, ip):
        log.debug('139 DPID %d: processing pending arpWait packet for ip %s' % (dpid, str(ip)))
        while len(self.arpWait[dpid][ip]) > 0:
            (bid, inport) = self.arpWait[dpid][ip][0]
            msg = of.ofp_packet_out(buffer_id=bid, in_port=inport)
            msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arpTable[dpid][ip]))
            msg.actions.append(of.ofp_action_output(port = self.routingTable[dpid][ip]))
            self.connections[dpid].send(msg)
            log.debug("146 DPID %d: sending arp wait packet, buffer id: %d, destip: %s, destmac: %s, output port: %d" % (dpid, bid, str(ip), str(self.arpTable[dpid][ip]), self.routingTable[dpid][ip]))
            del self.arpWait[dpid][ip][0]
        #print self.arpWait[dpid]

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

        log.debug("169 DPID %d, INPORT %d, answering for arp from %s: MAC for %s is %s", dpid, inport, str(a.protosrc), str(r.protosrc), str(r.hwsrc))
        self.connections[dpid].send(msg)


    def _generate_arp_request(self, packet, inport, dpid):
        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.hwlen = 6
        r.protolen = r.protolen
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = packet.next.dstip  # only thing that matters
        r.hwsrc = packet.src            # really doesn't matter in this case
        r.protosrc = packet.next.srcip  # also, really doesn't matter in this case
        e = ethernet(type=ethernet.ARP_TYPE, src=packet.src,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        log.debug("187 DPID %i, INPORT %i, sending ARP Request for %s on behalf of %s" % (dpid, inport, str(r.protodst), str(r.protosrc)))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.in_port = inport
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

            #print dir(p)
            #print type(p.payload)
        
        p_ip = ipv4()
        p_ip.protocol = p_ip.ICMP_PROTOCOL
        p_ip.srcip = dstip  # srcip, dstip in the argument is from the ping
        p_ip.dstip = srcip
        

        e = ethernet()
        e.src = p.dst
        e.dst = p.src
        e.type = e.IP_TYPE
        
        p_ip.payload = p_icmp
        e.payload = p_ip
        
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.data = e.pack()
        msg.in_port = self.routingTable[dpid][srcip]
        self.connections[dpid].send(msg)
        log.debug('229 DPID %d: IP %s pings router at %s, generating icmp reply with code %d...', dpid, str(srcip), str(dstip), icmp_type)


    def _learn_from_dpid(self, dpid, connection):
        if dpid not in self.connections:
            self.connections[dpid] = connection
        
        if dpid not in self.arpTable:
            self.arpTable[dpid] = {}
            for f in self.fakeways:
                self.arpTable[dpid][f] = dpid_to_mac(dpid)

        if dpid not in self.routingTable:
            self.routingTable[dpid] = {}

        if dpid not in self.arpWait:
            self.arpWait[dpid] = {}


    def _learn_route(self, ip, dpid, inport):
        if ip not in self.routingTable[dpid]:
            log.debug('250 DPID %d: Added IP %s into routing Table, output port %d' % (dpid, str(ip), inport))
            self.routingTable[dpid][ip] = inport
        else:
            log.debug('253 DPID %d: IP %s is in routing Table, RE_LEARNED, output port %d' % (dpid, str(ip), inport) )
    
    def _add_route_ipv4_flow_mod(self, p, dpid):
        msg = of.ofp_flow_mod()
        msg.idle_timeout = 3600
        msg.hard_timeout = 7200
        msg.priority = 1000
        msg.match.dl_type = 0x800 # ip packet
        msg.match.nw_dst = p.dstip
        msg.actions.append( of.ofp_action_dl_addr.set_dst(self.arpTable[dpid][p.dstip]) )
        msg.actions.append( of.ofp_action_output(port = self.routingTable[dpid][p.dstip]) )
        self.connections[dpid].send(msg)

    
    def _validate_ip(self, ip):
        ip_string = str(ip)
        l = ip_string.split('.')
        if l[0] != '10':
            log.debug("271 Invalid IP: %s"%ip_string )
            return False
        if l[1] != '0':
            log.debug("274 Invalid IP: %s"%ip_string )
            return False
        if l[2] != '1' and l[2] != '2' and l[2] != '3':
            log.debug("277 Invalid IP: %s"%ip_string )
            return False
        return True


    def _handle_PacketIn (self, event):
        packet = event.parsed # This is the parsed packet data.
        dpid = event.connection.dpid
        inport = event.port
        self._learn_from_dpid(dpid, event.connection)

        # error checking and sanitation
        if not packet.parsed:
            log.warning("290 Ignoring incomplete packet")
            return
        
        if packet.type == ethernet.LLDP_TYPE:
            # Ignore LLDP packets
            log.debug('295 Ignoring LLDP packet')
            return


        packet_in = event.ofp # The actual ofp_packet_in message.
        n = packet.next

        # deal with different packets
        if isinstance(n, ipv4):
            log.debug('304 DPID %d: IPv4 Packet, INPORT %d, IP %s => %s', dpid, inport, packet.next.srcip, packet.next.dstip)
            # learn the route
            self._learn_route(n.srcip, dpid, inport)
            if not self._validate_ip(n.dstip):
                self._generate_icmp_reply(dpid, packet, n.srcip, n.dstip, pkt.TYPE_DEST_UNREACH)
                return
            if n.dstip in self.fakeways:
                # there is an IPv4 packet destined to the router
                if isinstance(n.next, icmp):
                    log.debug("313 ICMP packet to this router")
                    if n.next.type == pkt.TYPE_ECHO_REQUEST:
                        self._generate_icmp_reply(dpid, packet, n.srcip, n.dstip, pkt.TYPE_ECHO_REPLY)
                        
            else:
                # need to check ARP
                if n.dstip not in self.routingTable[dpid] or n.dstip not in self.arpTable[dpid]:
                    # cache it and send ARP request
                    if n.dstip not in self.arpWait[dpid]:
                        self.arpWait[dpid][n.dstip] = []
                    entry = (packet_in.buffer_id, inport)
                    # push an entry in arpWait, send arp request and then wait
                    self.arpWait[dpid][n.dstip].append(entry)
                    log.debug('326 DPID %d, packet %s => %s, buffer_id %d, destination unknown, added to arpWait, prepare arp request' % (dpid, str(n.srcip), str(n.dstip), packet_in.buffer_id))
                    self._generate_arp_request(packet, inport, dpid)
                else:
                    #self._resend_packet (dpid, packet_in, self.routingTable[dpid][n.dstip])
                    msg = of.ofp_packet_out(buffer_id=packet_in.buffer_id, in_port=inport)
                    msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arpTable[dpid][n.dstip]))
                    msg.actions.append(of.ofp_action_output(port = self.routingTable[dpid][n.dstip]))
                    self.connections[dpid].send(msg)
                    log.debug('334 DPID %d, packet %s => %s, sent to port %d', dpid, str(n.srcip), str(n.dstip), self.routingTable[dpid][n.dstip])

                    self._add_route_ipv4_flow_mod(n, dpid)

        elif isinstance(n, arp):
#            print str(packet.src), '\n', str(packet.dst), '\n', str(packet.type), '\n', str(packet.parsed)
            self._learn_route(n.protosrc, dpid, inport)
            # redundent??? I deleted this if-statement
            if not self._validate_ip(n.protodst):
                self._generate_icmp_reply(dpid, packet, n.protosrc, n.protodst, pkt.TYPE_DEST_UNREACH)
                return
            self._process_arp_packet(n, inport, dpid, packet_in)


            


def launch (fakeways="10.0.1.1,10.0.2.1,10.0.3.1"):
    gateway_list = fakeways.split(',')
    fakeways = [IPAddr(x) for x in gateway_list]
    log.debug(str(fakeways))
    core.registerNew(Router, fakeways)
