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

struct route_table_entry* get_best_route(uint32_t ip_dest)
{
	/* Implement the LPM algorithm */
	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++). Entries in
	 * the rtable are in network order already */
	struct route_table_entry* best_entry = NULL;

	for (int i = 0; i < rtable_len; ++i) {
		if (rtable[i].prefix == (ip_dest & rtable[i].mask) &&
			(best_entry == NULL || best_entry->prefix < rtable[i].prefix)) {
			best_entry = &rtable[i];
		}
	}

	return best_entry;
}


struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	/* TODO 2.4: Iterate through the MAC table and search for an entry
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

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(*rtable) * MAX_RTABLE_LEN);
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "malloc failed");

	arp_table = malloc(sizeof(*arp_table) * MAX_ARP_TABLE_LEN);
	DIE(arp_table == NULL, "malloc failed");

	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		printf("We have received a packet\n");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be connected to
		host order. For example, ntohs(eth_hdr->ether_type). The opposite is needed when
		sending a packet on the link, */

		/* Check if we got an IPv4 packet */
		if (eth_hdr->ether_type != ntohs(ETHERTYPE_IP)) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}

		uint16_t check = ntohs(ip_hdr->check);
		ip_hdr->check = 0;
        uint16_t sum = checksum((uint16_t*)ip_hdr, sizeof(struct iphdr));
		if (sum != check) {
			printf("Dropped corrupted packet\n");
			continue;
		}

		/* Call get_best_route to find the most specific route, continue; (drop) if null */
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

		if (best_route == NULL) {
			printf("No route found\n");
			continue;
		}
	
		/* Check TTL >= 1. Update TLL. Update checksum  */
		if (ip_hdr->ttl < 1) {
			printf("TTL = 0; dropping packet\n");
			continue;
		}

		ip_hdr->ttl--;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		struct arp_table_entry *mac = get_arp_entry(ip_hdr->daddr);
		memcpy(eth_hdr->ether_dhost, mac->mac, 6);

		get_interface_mac(best_route->interface, eth_hdr->ether_shost);
		send_to_link(best_route->interface, buf, len);
	}
}
