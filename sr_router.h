/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_nat.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
    /*NAT*/
    struct sr_nat nat;
    int nat_active;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance*);
/*NEW FUNCTIONS*/
struct sr_if* findInterface(uint32_t,struct sr_instance*);
void handle_arp(struct sr_instance*,uint8_t *);
void handle_ip(struct sr_instance*,uint8_t *,unsigned int);
void handle_nat_ip(struct sr_instance*,uint8_t *,unsigned int,struct sr_if*);
void handle_nat_inbound(struct sr_instance*,uint8_t *,unsigned int,struct sr_if*);
void handle_nat_outbound(struct sr_instance*,uint8_t *,unsigned int,struct sr_if*);
uint8_t * generate_arp_reply(sr_arp_hdr_t *,uint32_t,unsigned char*);
void create_ethernet_header(uint8_t*,const uint8_t*,const uint8_t*,uint16_t);
void send_echo_reply(struct sr_instance*,uint32_t,uint32_t,sr_icmp_hdr_t*,unsigned int);
void create_ip_header(sr_ip_hdr_t*,uint32_t,int,uint32_t);
void ethernet_with_arp(struct sr_instance*,uint8_t*,unsigned int);
struct sr_rt* longest_prefix_match(struct sr_instance*,uint32_t);
uint16_t tcpcksum(sr_ip_hdr_t*, uint8_t *, unsigned int); 
void send_icmp(struct sr_instance*,uint32_t,uint8_t*,unsigned int,unsigned int);
#define ETHERNET_ADDRESS_LENGTH 6
#define ETHERNET_HEADER_LENGTH sizeof(sr_ethernet_hdr_t)
#define ARP_HEADER_LENGTH sizeof(sr_arp_hdr_t)

void sr_arp_broadcast(struct sr_instance *sr, struct sr_arpreq *arpreq);
void send_waiting_packets(struct sr_instance *sr, struct sr_arpreq *arpreq);
void generate_arp_request(struct sr_instance *sr, struct sr_arpreq *arpreq);
void handle_arp(struct sr_instance* sr,uint8_t * packet);
void handle_reply(struct sr_instance* sr,uint8_t * packet);

unsigned int check_check_sum(uint8_t *);
unsigned int check_len(uint8_t *, unsigned int);
unsigned int ethertype_len(uint16_t);

/* constants */
#define SR_ETH_HDR_LEN sizeof(sr_ethernet_hdr_t)
#define SR_ARP_HDR_LEN sizeof(sr_arp_hdr_t)



#endif /* SR_ROUTER_H */