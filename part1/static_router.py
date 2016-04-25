"""
Router Exercise

https://github.com/mininet/openflow-tutorial/wiki/Router-Exercise

make a static layer-3 forwarder/switch

ARP:
     1. arp cache
     2. ip to port dictionary
     3. message queue (while the router waits for an ARP reply)
     4. routing table (create a structure with all of the information statically assigned)

Static Routing
     * match IP address with appropriate port
     * change src and dest MAC address (behave like a router)

ICMP
     * need to respond to ICMP ping
     * support ICMP unreachable messages

reference: 
https://github.com/CPqD/RouteFlow/blob/master/pox/pox/forwarding/l3_learning.py


"""

from pox.core import core
import pox
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpidToStr
from pox.lib.recoco import Timer
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
import pox.lib.packet as pkt
import struct

log = core.getLogger()

def dpid_to_mac (dpid):
  # generate dummy MAC for switch
  return EthAddr("%012x" % (dpid & 0xffffffffffff | 0x0000000000f0,))

class Router (EventMixin):
  def __init__ (self, fakeways = []):
    log.debug('Initialize router')
    self.fakeways = fakeways

    # 1. An arp cache per dpid
    self.arpCache = {}

    # 2. ip to port dictionary per dpid
    # basically routing table
    self.routingTable = {}

    # for those who already sent an ARP request
    # now waiting for ARP response
    # each dpid has its own ARP waiting list
    # for each dpid, [ip] => list of (buffer_id, inport)
    self.arpQueue = {}

    self.listenTo(core)

  def _resend_packet (self, packet_in, out_port, event):
    """
    previous l2 learning switch's functionality

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
    event.connection.send(msg)

    self.listenTo(core)

  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow)
    log.debug("Up...")

  def _handle_ConnectionUp(self, event):
    log.debug("DPID %d is UP..." % event.dpid)

  def _register_dpid(self, dpid):
    # arpCache[dpid][ip] = data link address
    if dpid not in self.arpCache:
      self.arpCache[dpid] = {}
      for fakeway in self.fakeways:
          self.arpCache[dpid][fakeway] = dpid_to_mac(dpid)

    # routingTable[dpid][ip] = port
    if dpid not in self.routingTable:
      self.routingTable[dpid] = {}

    # arpQueue[dpid][ip] = (buffer_id, inport)
    if dpid not in self.arpQueue:
      self.arpQueue[dpid] = {}

  def _check_ip_exist(self, ip):
    ip_string = str(ip)
    l = ip_string.split('.')
    if l[0] != '10':
        log.debug("IP %s not on the network"%ip_string )
        return False
    if l[1] != '0':
        log.debug("IP %s not on the network"%ip_string )
        return False
    if l[2] != '1' and l[2] != '2' and l[2] != '3':
        log.debug("IP %s not on the network"%ip_string )
        return False
    return True

  def _ipv4_flow_mod(self, p, dpid, event):
    msg = of.ofp_flow_mod()
    msg.match.dl_type = 0x800 # ip packet
    msg.match.nw_dst = p.dstip
    msg.actions.append( of.ofp_action_dl_addr.set_dst(self.arpCache[dpid][p.dstip]) )
    msg.actions.append( of.ofp_action_output(port = self.routingTable[dpid][p.dstip]) )
    event.connection.send(msg)
    #https://openflow.stanford.edu/display/ONL/POX+Wiki#POXWiki-OpenFlowMessages

  def _icmp_reply(self, dpid, p, srcip, dstip, icmpType, event):
    pktIcmp = pkt.icmp()
    # TYPE_ECHO_REQUEST = 8, TYPE_DEST_UNREACH = 3, TYPE_ECHO_REPLY = 0
    if icmpType == pkt.TYPE_ECHO_REPLY:
      pktIcmp.payload = p.find('icmp').payload
    elif icmpType == pkt.TYPE_DEST_UNREACH:
      pktIcmp.type = pkt.TYPE_DEST_UNREACH
      unreachMsg = pkt.unreach()
      unreachMsg.payload = p.payload
      pktIcmp.payload = unreachMsg
      
    # Make IP header
    pktIp = ipv4()
    pktIp.protocol = pktIp.ICMP_PROTOCOL
    pktIp.srcip = dstip  
    pktIp.dstip = srcip

    # Ethernet header
    eth = ethernet()
    eth.src = p.dst
    eth.dst = p.src
    eth.type = eth.IP_TYPE

    # Hook them up
    pktIp.payload = pktIcmp # ICMP encapsulated in IP packet
    eth.payload = pktIp # IP packet encapsulated in ethernet frame

    # Send it back to the input port
    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
    msg.data = eth.pack()
    msg.in_port = self.routingTable[dpid][srcip]
    event.connection.send(msg)

    log.debug('DPID %d: IP %s pings %s, icmp reply with type %d', dpid, str(srcip), str(dstip), icmpType)
    log.debug('(type 0: reply, type 3: unreach, type 8: request)')
    # reference: https://github.com/hip2b2/poxstuff/blob/master/pong2.py

  def _arp_request(self, p, inport, dpid, event):
    # input p is data link layer packet
    r = arp()
    r.hwtype = r.HW_TYPE_ETHERNET
    r.prototype = r.PROTO_TYPE_IP
    r.hwlen = 6
    r.protolen = r.protolen
    r.opcode = r.REQUEST
    r.hwdst = ETHER_BROADCAST
    r.protodst = p.next.dstip # arp: who-has
    r.hwsrc = p.src
    r.protosrc = p.next.srcip # arp: tell me
    eth = ethernet(type=ethernet.ARP_TYPE, src=p.src, dst=ETHER_BROADCAST)
    eth.set_payload(r)
    log.debug("DPID %i port %i ARPing for %s on behalf of %s" % (dpid, inport,
     str(r.protodst), str(r.protosrc)))
    msg = of.ofp_packet_out()
    msg.data = eth.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.in_port = inport
    event.connection.send(msg)
    # reference: https://github.com/CPqD/RouteFlow/blob/master/pox/pox/forwarding/l3_learning.py

  def _arp_response(self, a, inport, dpid, event):
    r = arp()
    r.hwtype = a.hwtype
    r.prototype = a.prototype
    r.hwlen = a.hwlen
    r.protolen = a.protolen
    r.opcode = arp.REPLY
    r.hwdst = a.hwsrc
    r.protodst = a.protosrc
    r.protosrc = a.protodst
    r.hwsrc = self.arpCache[dpid][a.protodst]
    eth = ethernet(type=event.parsed.type, src=r.hwsrc, dst=a.hwsrc)
    eth.set_payload(r)
    log.debug("DPID %i port %i answering ARP for %s" % (dpid, inport, str(r.protosrc)))
    msg = of.ofp_packet_out()
    msg.data = eth.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
    msg.in_port = inport
    event.connection.send(msg)

  def _handle_PacketIn (self, event):
    e = event
    # packet: data link layer, packet.next: IP layer, packet.next.next: ICMP
    packet = e.parsed # This is the parsed packet data.
    dpid = e.connection.dpid
    inport = e.port

    # create dpid entry in all the tables
    self._register_dpid(dpid)

    # check packet
    if not packet.parsed:
        log.warning("Ignoring incomplete packet")
        return
    
    # in l3_learning.py, don't know if apply here
    if packet.type == ethernet.LLDP_TYPE:
        # Ignore LLDP packets
        log.debug('Ignoring LLDP packet')
        return

    packet_in = event.ofp # The actual ofp_packet_in message.

    if isinstance(packet.next,ipv4):
      log.debug("DPID: %i, port: %i, IP %s => %s" % (dpid,inport, packet.next.srcip,packet.next.dstip))

      # learn route
      if packet.next.srcip not in self.routingTable[dpid]:
        log.debug('Routing Table entry added, (DPID %d, IP %s) -> port %d' % (dpid, str(packet.next.srcip), inport))
        self.routingTable[dpid][packet.next.srcip] = inport
      else:
        log.debug('Routing Table entry RE-learned, (DPID %d, IP %s) -> port %d' % (dpid, str(packet.next.srcip), inport))

      # check if destination node is in fact in the network
      if (not self._check_ip_exist(packet.next.dstip)):
        # ICMP unreachable response
        self._icmp_reply(dpid, packet, packet.next.srcip, packet.next.dstip, pkt.TYPE_DEST_UNREACH, e)
        return

      # if the packet is for the router
      if packet.next.dstip in self.fakeways:
        # packet destined to router when its an icmp request
        if isinstance(packet.next.next, icmp):
          log.debug('ICMP request to router')
          if packet.next.next.type == pkt.TYPE_ECHO_REQUEST:
            self._icmp_reply(dpid, packet, packet.next.srcip, packet.next.dstip, pkt.TYPE_ECHO_REQUEST, e)
      else:
        # check with routing table and arp cache
        if packet.next.dstip not in self.routingTable[dpid] or packet.next.dstip not in self.arpCache[dpid]:
          # mayber a pending arp request...
          if packet.next.dstip not in self.arpQueue[dpid]:
            # if not, allocate an entry
            self.arpQueue[dpid][packet.next.dstip] = []
            self.arpQueue[dpid][packet.next.dstip].append((packet_in.buffer_id, inport))
            log.debug('ARP queue added: DPID %d, IP %s => %s, buffer_id %d, destination unknown, sending request' % (dpid, str(packet.next.srcip), str(packet.next.dstip), packet_in.buffer_id))
            self._arp_request(packet, inport, dpid, e)
        else:
          # found in table, forward
          msg = of.ofp_packet_out(buffer_id=packet_in.buffer_id, in_port=inport)
          msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arpCache[dpid][packet.next.dstip]))
          msg.actions.append(of.ofp_action_output(port = self.routingTable[dpid][packet.next.dstip]))
          e.connection.send(msg)
          log.debug('Packet forwarded: DPID %d, IP %s => %s, to port %d' % (dpid, str(packet.next.srcip), str(packet.next.dstip), self.routingTable[dpid][packet.next.dstip]))
          # pushing a flow
          self._ipv4_flow_mod(packet.next, dpid, e)

    elif isinstance(packet.next, arp):

      # learn 
      if packet.next.protosrc not in self.routingTable[dpid]:
        log.debug('Routing Table entry added, (DPID %d, IP %s) -> port %d' % (dpid, str(packet.next.protosrc), inport))
        self.routingTable[dpid][packet.next.protosrc] = inport
      else:
        log.debug('Routing Table entry RE-learned, (DPID %d, IP %s) -> port %d' % (dpid, str(packet.next.protosrc), inport))

      if (not self._check_ip_exist(packet.next.protodst)):
        # ICMP unreachable response
        self._icmp_reply(dpid, packet, packet.next.protosrc, packet.next.protodst, pkt.TYPE_DEST_UNREACH, e)
        return

      # process arp packet
      a = packet.next
      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:
            # Learn or update port/MAC info
            if a.protosrc not in self.arpCache[dpid]:
              self.arpCache[dpid][a.protosrc] = a.hwsrc
              log.debug('ARP entry added: DPID %d, IP = %s, MAC = %s' % (dpid, str(a.protosrc), str(a.hwsrc)))
              # maybe in arp queue
              if a.protosrc in self.arpQueue[dpid] and len(self.arpQueue[dpid][a.protosrc]) != 0:
                # process queue
                log.debug('DPID %d processing arpQueue request for ip %s' % (dpid, str(a.protosrc)))
                while len(self.arpQueue[dpid][a.protosrc]) > 0:
                  (bufferId, inport) = self.arpQueue[dpid][a.protosrc][0]
                  msg = of.ofp_packet_out(buffer_id=bufferId, in_port=inport)
                  msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arpCache[dpid][a.protosrc]))
                  msg.actions.append(of.ofp_action_output(port = self.routingTable[dpid][a.protosrc]))
                  e.connection.send(msg)
                  log.debug("DPIP %d ARP reply to entry in ARP queue: buffer id: %d, destip: %s, destmac: %s, port: %d" % (dpid, bufferId, str(a.protosrc), str(self.arpCache[dpid][a.protosrc]), self.routingTable[dpid][a.protosrc]))
                  del self.arpQueue[dpid][a.protosrc][0]

            if a.opcode == arp.REQUEST and a.protodst in self.fakeways:
              # Maybe we can answer
              self._arp_response(a,inport,dpid,e)
      else:
        # don't recognize the packet
        log.debug("Unknown ARP request: DPID %d flooding" % (dpid))
        self._resend_packet(packet_in, of.OFPP_FLOOD, e)

def launch (fakeways="10.0.1.1,10.0.2.1,10.0.3.1"):
    fakeways = fakeways.split(',')
    fakeways = [IPAddr(x) for x in fakeways]
    core.registerNew(Router, fakeways)
