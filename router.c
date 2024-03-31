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
	char debug_string[16];

	int best_pos = -1;

	int left = 0;
	int right = rtable_len - 1;

	inet_ntop(AF_INET, &ip_dest, debug_string, 16);
	printf("Looking for IP: %s\n", debug_string);
	while (left <= right) {
		int mid = (left + right) / 2;
		inet_ntop(AF_INET, &rtable[mid].prefix, debug_string, 16);
		printf("Comparing: %s with ", debug_string);

		int debug_int = ip_dest & rtable[mid].mask;
		inet_ntop(AF_INET, &debug_int, debug_string, 16);
		printf("%s\n", debug_string);

		if (rtable[mid].prefix == (ip_dest & rtable[mid].mask)) {
			best_pos = mid;
			break;
		} else if (ntohl(rtable[mid].prefix) > ntohl(ip_dest)) {
			right = mid - 1;
		} else {
			left = mid + 1;
		}
	}

	if (best_pos == -1) {
		return NULL;
	}

	while (best_pos < rtable_len - 2 && rtable[best_pos + 1].prefix == (ip_dest & rtable[best_pos + 1].mask)) {
		best_pos++;
	}

	return &rtable[best_pos];
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

int ip_compar(const void *ptr_e1, const void *ptr_e2)
{
	const struct route_table_entry e1 = *(struct route_table_entry*)ptr_e1;
	const struct route_table_entry e2 = *(struct route_table_entry*)ptr_e2;

	if (e1.prefix == e2.prefix) {
		return (ntohl(e1.mask) > ntohl(e2.mask)) - (ntohl(e1.mask) < ntohl(e2.mask));
	}

	return (ntohl(e1.prefix) > ntohl(e2.prefix)) - (ntohl(e1.prefix) < ntohl(e2.prefix));
}

void receive_ip_packet(struct ether_header *eth_hdr, int interface, size_t len)
{
	struct iphdr *ip_hdr = (struct iphdr *)((char *)eth_hdr + sizeof(*eth_hdr));
	int my_ip;
	inet_pton(AF_INET, get_interface_ip(interface), &my_ip);

	uint16_t check = ntohs(ip_hdr->check);
	ip_hdr->check = 0;
    uint16_t sum = checksum((uint16_t*)ip_hdr, sizeof(struct iphdr));
	if (sum != check) {
		printf("Dropped corrupted packet\n");
		return;
	}

	/* Check TTL >= 1. Update TLL. */
	if (ip_hdr->ttl < 1) {
		printf("TTL = 0; dropping packet\n");
		return;
	}

	ip_hdr->ttl--;

	if (ip_hdr->daddr == htons(my_ip)) {
		// responding to ICMP echo request

		struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + sizeof(*ip_hdr));

		icmp_hdr->type = 0;
		icmp_hdr->code = 0;

		// TODO
		printf("Packet drop cause of unfilled TODO");
	} else {
		// forwarding
		/* Call get_best_route to find the most specific route, continue; (drop) if null */
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

		if (best_route == NULL) {
			// destination unreachable
			printf("No route found\n");
			char packet[sizeof(struct ether_header) +
						sizeof(struct iphdr) +
						sizeof(struct icmphdr) + 64];
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
			new_ip->daddr = ip_hdr->saddr;
			new_ip->saddr = htonl(my_ip);
			new_ip->check = 0;
			// the ICMP is sent to the old sender
			new_ip->daddr = ip_hdr->saddr;
			new_ip->check = htons(checksum((uint16_t *)new_ip, sizeof(*new_ip)));

			// icmp
			struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)new_ip + sizeof(*new_ip));
			icmp_hdr->code = 0;
			icmp_hdr->type = 3;
			icmp_hdr->checksum = 0;
			icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(*icmp_hdr)));


			char *payload = (char *)icmp_hdr + sizeof(*icmp_hdr);
			char *old_payload = (char *)ip_hdr + sizeof(*ip_hdr) + sizeof(*icmp_hdr);
			memcpy(payload, old_payload, 64);

			const int packet_len = sizeof(struct ether_header) +
						sizeof(struct iphdr) +
						sizeof(struct icmphdr) + 64;
			printf("%d", packet_len);
			send_to_link(interface, packet, packet_len);
			return;
		}

		// update L2 src and dest
		struct arp_table_entry *dest_mac = get_arp_entry(best_route->next_hop);
		memcpy(eth_hdr->ether_dhost, dest_mac->mac, 6);
		get_interface_mac(best_route->interface, eth_hdr->ether_shost);

		/* Update checksum */	
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		send_to_link(best_route->interface, (char *)eth_hdr, len);
	}

}

void receive_arp_request(struct ether_header *eth_hdr, int interface, size_t len)
{
	// TODO
	return;
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

	// sorting the rtable for binary searching the IPs
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), ip_compar);

	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

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
			receive_arp_request(eth_hdr, interface, len);
		} else {
			printf("Invalid ETHERTYPE\n");
		}
	}
}
