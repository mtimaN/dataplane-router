#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "queue.h"
#include "lib.h"
#include "protocols.h"


/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_table_entry *arp_table;
int arp_table_len;

queue arp_queue;

struct route_table_entry* get_best_route(uint32_t ip_dest)
{
	/* Implement the LPM algorithm */
	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++). Entries in
	 * the rtable are in network order already */
	char debug_string[16];

	int best_pos = -1;

	int left = 0;
	int right = rtable_len - 1;

	inet_ntop(AF_INET, &ip_dest, debug_string, 16);
	printf("Looking for next hop to: %s\n", debug_string);

	while (left <= right) {
		int mid = (left + right) / 2;

		inet_ntop(AF_INET, &rtable[mid].prefix, debug_string, 16);
		printf("Checking prefix %s\n", debug_string);
		if (rtable[mid].prefix == (ip_dest & rtable[mid].mask)) {
			best_pos = mid;
			left = mid + 1;
		} else if (ntohl(rtable[mid].prefix) > ntohl(ip_dest)) {
			right = mid - 1;
		} else {
			left = mid + 1;
		}
	}

	if (best_pos == -1) {
		return NULL;
	}

	while (best_pos < rtable_len - 1 && rtable[best_pos + 1].prefix == (ip_dest & rtable[best_pos + 1].mask)) {
		best_pos++;
	}

	return &rtable[best_pos];
}


struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	/* Iterate through the MAC table and search for an entry
	 * that matches given_ip. */

	/* We can iterate through the arp_table for (int i = 0; i <
	 * arp_table_len; i++) */
	for (int i = 0; i < arp_table_len; ++i) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

int ip_compar(const void *ptr_e1, const void *ptr_e2)
{
	const struct route_table_entry e1 = *(struct route_table_entry*)ptr_e1;
	const struct route_table_entry e2 = *(struct route_table_entry*)ptr_e2;

	if (e1.prefix == e2.prefix) {
		return (ntohl(e1.mask) > ntohl(e2.mask)) - (ntohl(e1.mask) < ntohl(e2.mask));
	}

	return (ntohl(e1.prefix) > ntohl(e2.prefix)) - (ntohl(e1.prefix) < ntohl(e2.prefix));
}

void send_icmp(struct ether_header *eth_hdr, int interface, int my_ip, int type)
{
	struct iphdr *ip_hdr = (struct iphdr *)((char *)eth_hdr + sizeof(*eth_hdr));

	char packet[sizeof(struct ether_header) +
	sizeof(struct iphdr) +
	sizeof(struct icmphdr) + 8];
	memset(packet, 0, sizeof(packet));

	// ethernet
	struct ether_header *new_eth = (struct ether_header *)packet;

	// give the frame back
	memcpy(new_eth->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, new_eth->ether_shost);

	new_eth->ether_type = htons(ETHERTYPE_IP);

	// ip
	struct iphdr *new_ip = (struct iphdr *)((char *)new_eth + sizeof(*new_eth));
	new_ip->version = 4;
	new_ip->ihl = 5;
	new_ip->tos = 0;
	new_ip->tot_len = htons((sizeof(struct iphdr) + sizeof(struct icmphdr) + 64));
	new_ip->id = htons(1);
	new_ip->frag_off = htons(0);
	new_ip->ttl = 64;
	new_ip->protocol = 0x01; // ICMP protocol number
	// the ICMP is sent to the old sender
	new_ip->daddr = ip_hdr->saddr;
	new_ip->saddr = my_ip;
	new_ip->check = 0;
	new_ip->check = htons(checksum((uint16_t *)new_ip, sizeof(*new_ip)));

	// icmp
	struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)new_ip + sizeof(*new_ip));
	icmp_hdr->code = 0;
	icmp_hdr->type = type;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(*icmp_hdr)));


	char *payload = (char *)icmp_hdr + sizeof(*icmp_hdr);
	char *old_payload = (char *)ip_hdr + sizeof(*ip_hdr) + sizeof(*icmp_hdr);
	memcpy(payload, old_payload, 8);

	const int packet_len = sizeof(struct ether_header) +
	sizeof(struct iphdr) +
	sizeof(struct icmphdr) + 8;

	printf("Sending ICMP\n");
	send_to_link(interface, packet, packet_len);
}

void broadcast_arp_request(int interface, uint32_t ip, uint32_t source_ip)
{
	char *buffer = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
	struct ether_header *eth_hdr = (struct ether_header *)buffer;

	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	get_interface_mac(interface, eth_hdr->ether_shost);
	memset(eth_hdr->ether_dhost, 0xff, 6);

	struct arp_header *arp_hdr = (struct arp_header *)((char *)eth_hdr + sizeof(*eth_hdr));
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(ETHERTYPE_IP);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	memcpy(arp_hdr->sha, eth_hdr->ether_shost, 6);
	arp_hdr->spa = source_ip;
	
	memset(arp_hdr->tha, 0, 6);
	arp_hdr->tpa = ip;

	for (int i = 0; i < ROUTER_NUM_INTERFACES; ++i) {
		if (i != interface) {
			printf("Broadcasting ARP REQUEST to %d\n", i);
			send_to_link(i, buffer, sizeof(*eth_hdr) + sizeof(*arp_hdr));
		}
	}
	free(buffer);
}

void receive_ip_packet(struct ether_header *eth_hdr, int interface, size_t len)
{
	struct iphdr *ip_hdr = (struct iphdr *)((char *)eth_hdr + sizeof(*eth_hdr));
	uint32_t my_ip;
	inet_pton(AF_INET, get_interface_ip(interface), &my_ip);
	char debug_string[16];
	printf("My ip: %s\n", get_interface_ip(interface));
	uint16_t check = ntohs(ip_hdr->check);
	ip_hdr->check = 0;
    uint16_t sum = checksum((uint16_t*)ip_hdr, sizeof(struct iphdr));
	if (sum != check) {
		printf("Dropped corrupted packet\n");
		return;
	}

	/* Check TTL > 1. Update TTL. */
	if (ip_hdr->ttl <= 1) {
		printf("TTL = 0; dropping packet\n");
		send_icmp(eth_hdr, interface, my_ip, 11);
		return;
	}

	ip_hdr->ttl--;

	/* Update checksum */	
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	if (ip_hdr->daddr == my_ip) {
		// responding to ICMP echo request
		struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + sizeof(*ip_hdr));

		// swap source and destination
		char buffer[6];
		memcpy(buffer, eth_hdr->ether_dhost, sizeof(buffer));
		memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
		memcpy(eth_hdr->ether_shost, buffer, sizeof(eth_hdr->ether_shost));

		ip_hdr->daddr = ip_hdr->saddr; 
		ip_hdr->saddr = my_ip;
		ip_hdr->ttl = 64;
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

		icmp_hdr->type = 0;
		icmp_hdr->code = 0;
		icmp_hdr->checksum = 0;
		icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(*icmp_hdr)));

		printf("Sending ICMP echo request\n");
		send_to_link(interface, (char *)eth_hdr, len);
		return;
	} else {
		// forwarding
		/* Call get_best_route to find the most specific route */
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

		if (best_route == NULL) {
			// destination unreachable
			printf("No route found\n");
			send_icmp(eth_hdr, interface, my_ip, 3);
			return;
		}


		get_interface_mac(best_route->interface, eth_hdr->ether_shost);

		// update L2 src and dest
		struct arp_table_entry *dest_mac = get_arp_entry(best_route->next_hop);
		
		if (dest_mac == NULL) {
			// send ARP request
			struct arp_queue_entry *entry = malloc(sizeof(*entry));
			entry->buffer = malloc(len);
			memcpy(entry->buffer, eth_hdr, len);
			entry->interface = best_route->interface;
			entry->len = len;
			queue_enq(arp_queue, entry);

			inet_ntop(AF_INET, &ip_hdr->daddr, debug_string, sizeof(debug_string));
			printf("DADDR: %s\n", debug_string);	
			broadcast_arp_request(interface, best_route->next_hop, my_ip);
			return;
		}

		memcpy(eth_hdr->ether_dhost, dest_mac->mac, sizeof(dest_mac->mac));

		inet_ntop(AF_INET, &best_route->next_hop, debug_string, sizeof(debug_string));
		printf("Sending to %s\n", debug_string);
		send_to_link(best_route->interface, (char *)eth_hdr, len);
	}
}

void receive_arp_packet(struct ether_header *eth_hdr, int interface, size_t len)
{
	struct arp_header *arp_hdr = (struct arp_header *)((char *)eth_hdr + sizeof(*eth_hdr));
	uint32_t my_ip;
	inet_pton(AF_INET, get_interface_ip(interface), &my_ip);

	char debug_string[16];
	inet_ntop(AF_INET, &my_ip, debug_string, 16);
	printf("My ip: %s\n", debug_string);
	inet_ntop(AF_INET, &arp_hdr->tpa, debug_string, 16);
	printf("Target: %s\n", debug_string);

	if (ntohs(arp_hdr->op) == 1 && arp_hdr->tpa == my_ip) {
		// REQUEST
		// swap source and destination
		char buffer[6];
		memcpy(buffer, eth_hdr->ether_dhost, sizeof(buffer));
		memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
		memcpy(eth_hdr->ether_shost, buffer, sizeof(eth_hdr->ether_shost));

		arp_hdr->op = 2;

		memcpy(arp_hdr->tha, eth_hdr->ether_dhost, sizeof(arp_hdr->tha));
		arp_hdr->tpa = arp_hdr->spa;

		memcpy(arp_hdr->sha, eth_hdr->ether_shost, sizeof(arp_hdr->sha));
		arp_hdr->spa = my_ip;

		printf("Sending ARP REPLY\n");
		send_to_link(interface, (char *)eth_hdr, len);
	} else if (ntohs(arp_hdr->op) == 2) {
		// REPLY

		char debug_string[16];
		if (queue_empty(arp_queue)) {
			// DROP packet
			printf("Empty q, dropped packet\n");
			return;
		}

		printf("q NOT EMPTY\n");
		struct arp_queue_entry *entry = queue_deq(arp_queue);
		struct ether_header *queued_hdr = (struct ether_header *)entry->buffer;
		struct iphdr *queued_ip_hdr = (struct iphdr *)((char *)queued_hdr + sizeof(*queued_hdr));

		int i = 0;

		while (++i < 10 && queued_ip_hdr->daddr != arp_hdr->spa) {

			// DEBUG
			uint32_t debug_int = queued_ip_hdr->daddr;
			inet_ntop(AF_INET, &debug_int, debug_string, sizeof(debug_string));
			printf("%s is not", debug_string);
			inet_ntop(AF_INET, &arp_hdr->spa, debug_string, sizeof(debug_string));
			printf(" %s\n", debug_string);

			// /DEBUG

			queue_enq(arp_queue, entry);
			entry = queue_deq(arp_queue);
			queued_hdr = (struct ether_header *)entry->buffer;
			queued_ip_hdr = (struct iphdr *)((char *)queued_hdr + sizeof(*queued_hdr));
		}

		if (i == 10) {
			printf("Invalid ARP reply\n");
			queue_enq(arp_queue, entry);
			return;
		}

		// add to ARP table
		memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, sizeof(arp_hdr->sha));
		arp_table[arp_table_len++].ip = arp_hdr->spa;

		memcpy(queued_hdr->ether_dhost, arp_hdr->sha, sizeof(arp_hdr->sha));
		printf("Sending QUEUED PACKET\n");
		send_to_link(entry->interface, entry->buffer, entry->len);
		free(entry->buffer);
		free(entry);
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(*rtable) * MAX_RTABLE_LEN);
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "malloc failed");

	arp_queue = queue_create();
	arp_table = malloc(sizeof(*arp_table) * MAX_ARP_TABLE_LEN);
	DIE(arp_table == NULL, "malloc failed");

	rtable_len = read_rtable(argv[1], rtable);

	// sorting the rtable for binary searching the IPs
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), ip_compar);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be connected to
		host order. For example, ntohs(eth_hdr->ether_type). The opposite is needed when
		sending a packet on the link, */

		/* Check if we got an IPv4 packet */
		if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP)) {
			receive_ip_packet(eth_hdr, interface, len);
			continue;
		} else if (eth_hdr->ether_type == ntohs(ETHERTYPE_ARP)) {
			receive_arp_packet(eth_hdr, interface, len);
		} else {
			printf("Invalid ETHERTYPE\n");
		}
	}
}
