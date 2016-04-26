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



