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
	int best_pos = -1;

	int left = 0;
	int right = rtable_len - 1;

	while (left <= right) {
		int mid = (left + right) / 2;

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
	struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + sizeof(*ip_hdr));
	size_t len = sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*icmp_hdr);
	if (type == 11 || type == 3) {
		len += 8;
	}

	// swap source and destination
	char buffer[6];
	memcpy(buffer, eth_hdr->ether_dhost, sizeof(buffer));
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
	memcpy(eth_hdr->ether_shost, buffer, sizeof(eth_hdr->ether_shost));

	ip_hdr->daddr = ip_hdr->saddr; 
	ip_hdr->saddr = my_ip;
	ip_hdr->ttl = 64;
	ip_hdr->check = 0;
	ip_hdr->protocol = 0x01; // ICMP protocol number
	ip_hdr->tot_len = htons(len);
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));
	ip_hdr->frag_off = 0;
	ip_hdr->id = htons(1);

	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(*icmp_hdr)));


	printf("Sending ICMP echo reply\n");
	send_to_link(interface, (char *)eth_hdr, len);
	return;
}

void broadcast_arp_request(struct route_table_entry *route)
{
	char *buffer = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
	struct ether_header *eth_hdr = (struct ether_header *)buffer;

	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	get_interface_mac(route->interface, eth_hdr->ether_shost);
	memset(eth_hdr->ether_dhost, 0xff, sizeof(eth_hdr->ether_dhost));

	struct arp_header *arp_hdr = (struct arp_header *)((char *)eth_hdr + sizeof(*eth_hdr));
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(ETHERTYPE_IP);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	memcpy(arp_hdr->sha, eth_hdr->ether_shost, sizeof(arp_hdr->sha));
	arp_hdr->spa = inet_addr(get_interface_ip(route->interface));
	
	memset(arp_hdr->tha, 0, sizeof(arp_hdr->tha));
	arp_hdr->tpa = route->next_hop;

	send_to_link(route->interface, buffer, sizeof(*eth_hdr) + sizeof(*arp_hdr));
	free(buffer);
}

void receive_ip_packet(struct ether_header *eth_hdr, int interface, size_t len)
{
	struct iphdr *ip_hdr = (struct iphdr *)((char *)eth_hdr + sizeof(*eth_hdr));
	uint32_t my_ip;
	inet_pton(AF_INET, get_interface_ip(interface), &my_ip);

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
		send_icmp(eth_hdr, interface, my_ip, 0);
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
			entry->next_route = best_route;
			entry->len = len;
			queue_enq(arp_queue, entry);
			printf("Interface: %d", best_route->interface);
			broadcast_arp_request(best_route);
			return;
		}

		memcpy(eth_hdr->ether_dhost, dest_mac->mac, sizeof(dest_mac->mac));

		send_to_link(best_route->interface, (char *)eth_hdr, len);
	}
}

void receive_arp_packet(struct ether_header *eth_hdr, int interface, size_t len)
{
	struct arp_header *arp_hdr = (struct arp_header *)((char *)eth_hdr + sizeof(*eth_hdr));
	uint32_t my_ip;
	inet_pton(AF_INET, get_interface_ip(interface), &my_ip);

	if (ntohs(arp_hdr->op) == 1 && arp_hdr->tpa == my_ip) {
		// REQUEST
		printf("Request received\n");
		memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
		get_interface_mac(interface, eth_hdr->ether_shost);

		arp_hdr->op = htons(2);

		memcpy(arp_hdr->tha, eth_hdr->ether_dhost, sizeof(arp_hdr->tha));
		arp_hdr->tpa = arp_hdr->spa;

		memcpy(arp_hdr->sha, eth_hdr->ether_shost, sizeof(arp_hdr->sha));
		arp_hdr->spa = my_ip;

		send_to_link(interface, (char *)eth_hdr, len);
	} else if (ntohs(arp_hdr->op) == 2) {
		// REPLY
		if (queue_empty(arp_queue)) {
			// DROP packet
			printf("Unwanted reply\n");
			return;
		}

		size_t max_it = get_queue_size(arp_queue);
		struct arp_queue_entry *entry = queue_deq(arp_queue);
		struct route_table_entry *next_route = entry->next_route;
		size_t i = 0;

		while (++i <= max_it && next_route->next_hop != arp_hdr->spa) {
			queue_enq(arp_queue, entry);
			entry = queue_deq(arp_queue);
			next_route = entry->next_route;
		}

		if (i > max_it) {
			printf("Unwanted reply\n");
			queue_enq(arp_queue, entry);
			return;
		}

		// add to ARP table
		memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, sizeof(arp_hdr->sha));
		arp_table[arp_table_len++].ip = arp_hdr->spa;

		struct ether_header *queued_hdr = (struct ether_header *)entry->buffer;
		memcpy(queued_hdr->ether_dhost, arp_hdr->sha, sizeof(arp_hdr->sha));
		printf("Sending QUEUED PACKET\n");
		send_to_link(entry->next_route->interface, entry->buffer, entry->len);
		free(entry->buffer);
		free(entry);
	} else {
		printf("Received redundant arp request\n");
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

	// arp_table_len = parse_arp_table("arp_table.txt", arp_table);

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
