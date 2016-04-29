# OpenFlow applications using MININET and POX Controller - part 2

static_router.py in part 1 is modified to support subnet routing

## [Router Exercise](https://github.com/mininet/openflow-tutorial/wiki/Router-Exercise)
router exercise was repeated with a different topology (see below)

##### router.py
make a static layer-3 forwarder/switch, which supports:
- ARP
  - controller constructs ARP replies and forward them out the appropriate ports.
- static routing
  - forward ipv4 traffic to the correct subnet.
  - only change packet's source and destination MAC address
- ICMP
  - controller may receive ICMP echo (ping) requests for the router, which it should respond to.
  - packets for unreachable subnets should be responded to with ICMP network unreachable messages.

##### mytopo2.py
create the following topology
```
                                host5(h5)
                                  | 
   host1(h1) -- switch(s1) -- switch(s2) -- host3(h3)
                   |              |
                host2(h2)       host4(h4)
```
##### To simulate
- open two console: one for mininet, one for the controller
- create topology in mininet console
make sure mytopo1.py is in the mininet directory
```
sudo mn --custom ~/mininet/mytopo2.py --topo mytopo --mac --controller=remote,ip=127.0.0.1
```
- start controller in controller console
```
./pox.py log.level --DEBUG misc.router misc.full_payload
```

##### pseudocode for handling a packet arrival
```
(“I” denotes the router)

Create tables for the DPID if they do not already exist in ARP cache, routing table, and ARP queue
Check if it’s a valid packet
If the packet is an IPv4 instance:
  Log the source IP in the associated routing table if it’s not already in it
  Check if the destination is valid
  if the packet is for “me”
    If the packet is an ICMP request, then “I” reply
  Else if the destination and source are on the same subnet
    If destination IP is found in both routing table and ARP cache
      Forward the packet
      Install a flow entry
    Else: 
      If the destination IP is not found in ARP queue:
        “I” have to send ARP request  to get the MAC address
  Else if the destination is on a different subnet
    Iterate through subnet router table to find an IP with the same network address
    Consult ARP cache and routing table for next hop MAC and outgoing port
    Forward the packet
    Install a flow entry

else if the packet is an ARP instance:
  if it is  an Ethernet packet:
    Log the source IP in the associate routing table if it’s not already in it
  Check if the destination is valid
  If the source IP address is not in the associated ARP cache
    Add an entry
    If the source IP address matches a pending request in ARP queue
      “I” forward the ARP reply
  If the ARP instance is a request for me
    “I” send ARP reply
Else:
  Flood the packet
```

