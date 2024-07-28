# Dataplane Router

## Matei Mantu

## Group: 322CA

### Introduction

This router is made to:

- forward IPv4 packets
- send and receive ARP requests and replies in order to dynamically populate the ARP table.
- send ICMP packets reporting destination unreachable or time exceeded errors.
- reply to ICMP echo requests

Some details regarding the implementation:

### IPv4:

- it uses a static routing table
- LPM is determined using binary search. The routing table entries are initially sorted first by prefix and then by mask length. After an O(nlogn) initial computation, it is able to route packets in O(logn).
- The next hop is then searched for in the ARP table.

### Dynamic ARP:

- the ARP table is filled "on the go". After the router gets the next hop it looks it up in the arp table. If it is not present, it broadcasts and ARP request to the next hop interface, expecting a reply. Meanwhile, the packet is saved in a queue.
- The ARP table entries are searched linearly, as the table size is very small.
- After it receives an ARP reply, it iterates through the queue in order to find the packet to be sent and saves the MAC address of the sender for further use. The packet is then sent to the next hop.
- It is also configured to respond to ARP requests by sending back the MAC address of the interface of the request.

### ICMP:

- If the TTL of the received packet is 1 or less, it drops it, sending an ICMP request to the sender in order to notify them.
- If the Host is unreachable(i.e. there is no `next hop` found using the LPM algorithm), the packet is again dropped and the sender is notified.
- If the router receives an ICMP echo request, it answers back.
- I decided to modify the received packet instead of building a new one, for efficiency reasons.

### Notes:

- I modified the given queue in order to get the size in O(1).
- I learned a lot by making this homework. I used `Wireshark` for debugging and `ping`, `arping` for testing locally( alongside printfs).
- I added some defines to lib.h as I saw fit.