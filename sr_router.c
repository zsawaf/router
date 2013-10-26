/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
static const uint8_t ARP_MAC_BROADCAST [ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
#define SR_ARP_MAXSEND    5.0        
#define SR_ARP_MAXDIF     1.0



void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);
    printf("hello word\n");
    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  
  printf("*** -> Received packet of length %d \n",len);
  print_hdrs(packet,len);
  /* fill in code here */
  

  /*GET THE PROTOCOL OF THE ETHERNET PACKET*/
  uint16_t ethprotocol = ntohs(((sr_ethernet_hdr_t*)packet)->ether_type);
  
  printf("-----\nProtocol : 0x%04x\n",ethprotocol);
  
  if(ethprotocol == ethertype_arp){
    printf("Packet protocol is ARP\n-----\n");
    /*Handle ARP PACKET*/
    handle_arp(sr,packet);
  }
  else if(ethprotocol == ethertype_ip){
        printf("Packet protocol is IP\n-----\n");
        handle_ip(sr,packet);
      }
}/* end sr_ForwardPacket */

/*
 * Function to handle IP.
 */
void handle_ip(struct sr_instance* sr,uint8_t * packet)
{
  sr_ip_hdr_t* ipPacket = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
  uint8_t protocol = ipPacket -> ip_p;
  printf("---------------------------------\n");
  printf("Protocol is %d\n",protocol);
  if(protocol==1)
    {
    /*Handle ICMP packet*/
    printf("ICMP ");

    /* Check if mac address exists */
    /* Get source mac */
    printf("Got the mac address.\n");


    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + SR_ETH_HDR_LEN);

    /* dest ip */
    uint32_t ip = ip_header->ip_dst;
 
    printf("Finished getting the right interface.\n");
    enqueue_packet(sr, ip, packet);

    }
}/* end sr_ForwardPacket */


/* --------- Helper Functions ------ */
void handle_arp(struct sr_instance* sr,uint8_t * packet)
{
  sr_arp_hdr_t* arpPacket = (sr_arp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));   
  uint32_t tip = ntohl(arpPacket -> ar_tip); print_addr_ip_int(tip);
  
  unsigned short arp_type = ntohs(arpPacket -> ar_op); 
  printf("Operation is %d\n",arp_type);
  struct sr_if* interface = findInterface(tip,sr);
   printf("---------------------------------\n");
  if(interface)
    {
      printf("Request matches Interface\n");
      if(arp_type == arp_op_request)
    {
      uint8_t * reply = generate_arp_reply(arpPacket, interface->ip, interface->addr);
     
      int sent = sr_send_packet(sr,reply,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t),interface->name);
    
      printf("Trying to send the ARP reply :\n");
      print_hdrs(reply,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
    
      if(sent)
       printf("ARP reply not sent, an error occured.\n");
     else
       printf("ARP reply successfully sent.\n");
    }
      else
    if(arp_type == arp_op_reply)
      {
	 handle_reply(sr, packet);
      }
    if(arp_type==2) {
      printf("\n\n\nI am going to send a reply now\n\n\n");
      handle_reply(sr, packet);
    }
        else
          printf("Invalid operation type");
      }
  else
    printf("Does not match any interface | Ignore the packet");
   
      printf("---------------------------------\n");
  
}

/*------------------------------------------------------------------------------------*/
void create_ethernet_header(uint8_t* reply, const uint8_t* destination, const uint8_t* sender, uint16_t type)
{
  memcpy(((sr_ethernet_hdr_t*)reply)->ether_dhost, destination, ETHER_ADDR_LEN);
  memcpy(((sr_ethernet_hdr_t*)reply)->ether_shost, sender, ETHER_ADDR_LEN);
  ((sr_ethernet_hdr_t*)reply)->ether_type = htons(type);
}

/*
 * Create and send the ARP request
 */
void generate_arp_request(struct sr_instance *sr, struct sr_arpreq *arpreq) {

  printf("sending ARP REQUEST\n\n\n\n\\n\n\n\n\n");

    time_t now = time(NULL);
    time_t last_sent = arpreq->sent;

    if (difftime(now, last_sent) > SR_ARP_MAXDIF) { 
        if (arpreq->times_sent < SR_ARP_MAXSEND) {

        uint8_t * request = (uint8_t *) malloc(SR_ETH_HDR_LEN + SR_ARP_HDR_LEN);

        /* find out-going interface */
        struct sr_rt *routing_table = sr_search_ip_prfx(sr, arpreq->ip);
        const char *iface_name = routing_table->interface;				
        struct sr_if *iface = sr_get_interface(sr, iface_name);

        /* create the ethernet header - USER FUNCTION FOR THIS */
        memcpy(((sr_ethernet_hdr_t*)request)->ether_dhost, ARP_MAC_BROADCAST, ETHER_ADDR_LEN);
        memcpy(((sr_ethernet_hdr_t*)request)->ether_shost, iface->addr, ETHER_ADDR_LEN);

        ((sr_ethernet_hdr_t*)request)->ether_type = htons(ethertype_arp);

        /* create & populate the ARP header */
        sr_arp_hdr_t * arp_request = (sr_arp_hdr_t*) (request + sizeof(sr_ethernet_hdr_t));
        arp_request->ar_op = htons(arp_op_request);
        memcpy(arp_request->ar_sha, iface->addr, ETHER_ADDR_LEN);
        memcpy(arp_request->ar_tha, ARP_MAC_BROADCAST, ETHER_ADDR_LEN);
        arp_request->ar_sip = iface->ip;
        arp_request->ar_tip =arpreq->ip;
        arp_request->ar_pro=ntohs(ethertype_ip);
        arp_request->ar_hrd=ntohs(arp_hrd_ethernet);
        arp_request->ar_hln=6;
        arp_request->ar_pln=4;

        /*printf("TEST NOW==============================");
        print_addr_ip_int(iface->ip);
        print_addr_ip_int(arpreq->ip);
        printf("END TEST==============================\n\n\n"); */

        sr_send_packet(sr, request, SR_ETH_HDR_LEN + SR_ARP_HDR_LEN, iface->name);

        /* update request information */
        arpreq->times_sent += 1;
        arpreq->sent = now;
        }

        /* destroy packet because it's been sent too many times or expired */
        else {
            sr_arpreq_destroy(&sr->cache, arpreq);
        }
    }
    else {
        sr_arpreq_destroy(&sr->cache, arpreq);
    }
}

void enqueue_packet(struct sr_instance* sr, uint32_t destination_ip,  uint8_t *packet) {
    
    /* fetch entry based on interface's IP */
    struct sr_rt *routing_table = sr_search_ip_prfx(sr, destination_ip);
    uint32_t target_ip = routing_table->gw.s_addr;
    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, target_ip);

    if (entry) {
        /* forward the packet */
    }

    else {
     
     /* put packet to wait on the reply */
    struct sr_arpreq *arp_request = sr_arpcache_queuereq(&sr->cache, target_ip, packet, (SR_ETH_HDR_LEN + sizeof(sr_icmp_hdr_t) + SR_ARP_HDR_LEN),routing_table->interface);

    /*  send first ARP request - MIGHT BE UNNCESESSARY */
    generate_arp_request(sr, arp_request);
    }
}

/*
*
*/
uint8_t * generate_arp_reply(sr_arp_hdr_t * request,uint32_t ip,unsigned char* mac)
{
  uint8_t * reply = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
 
  create_ethernet_header(reply,request->ar_sha,mac,ethertype_arp);
  sr_arp_hdr_t * arp_reply = (sr_arp_hdr_t*) (reply + sizeof(sr_ethernet_hdr_t));
  
  arp_reply->ar_op = htons(arp_op_reply);
  
  memcpy(arp_reply->ar_sha, mac, ETHER_ADDR_LEN);
  memcpy(arp_reply->ar_tha, request->ar_sha, ETHER_ADDR_LEN);
  arp_reply->ar_sip = ip;
  arp_reply->ar_tip = request->ar_sip ;
  arp_reply->ar_pro=ntohs(ethertype_ip);
  arp_reply->ar_hrd=ntohs(arp_hrd_ethernet);
  arp_reply->ar_hln=6;
  arp_reply->ar_pln=4;
 
  return reply;

}

/*
* Return the longest prefix match for 'ip'
* in sr's routing table, if not found, return NULL.
*/
struct sr_rt * sr_search_ip_prfx(struct sr_instance * sr, uint32_t ip){

    struct sr_rt * curr_rt = sr->routing_table;
    struct sr_rt * res_rt = NULL;
    uint32_t subnetwork;
    int i=0;

    /* Iterate through curr_rt's linked list and find the best match */
    while(curr_rt){
        subnetwork = curr_rt->dest.s_addr & curr_rt->mask.s_addr;

        /* Now we do the IP match up */
        if (subnetwork == (ip & curr_rt->mask.s_addr)){

            /* fill out first time */
            if (!res_rt) {
                res_rt = curr_rt;
            }
            else {
                if(ntohl(res_rt->mask.s_addr) < ntohl(curr_rt->mask.s_addr)) {
                    res_rt = curr_rt;
                }
            }
        }
        curr_rt = curr_rt->next;
	   i++;
    }
    return res_rt;
}

struct sr_if* findInterface(uint32_t ip,struct sr_instance* sr)
{
 struct sr_if* iflist = sr->if_list;
    while(iflist)
      {
    if(ip==ntohl(iflist -> ip))
      return iflist;
    iflist = iflist -> next;
      }
    return 0;
}

/*
* Send the packets waiting on the reply to the ARP request
*/
void send_waiting_packets(struct sr_instance *sr, struct sr_arpreq *arpreq){

    /*Do a cache look up. */
    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, arpreq->ip);

    if(entry) {

        struct sr_packet *packets = arpreq->packets;
        while (packets) {

        	/* change the target and source MAC addresses */
        	sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t*) packets->buf;
        	memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        	memcpy(eth_hdr->ether_shost, sr_get_interface(sr, packets->iface)->addr, ETHER_ADDR_LEN);
        	
        	printf("sending packet \n");

            sr_send_packet(sr, packets->buf, packets->len, packets->iface);
            struct sr_packet *new_packet = packets->next;
        	/*free(packets->buf);
                free(&packets->len);
                free(packets->iface);*/
            packets = new_packet;
        }
    }
}

void handle_reply(struct sr_instance* sr,uint8_t * packet) {

    /* initialize variables */
    sr_arp_hdr_t *ARP_header;
    struct sr_if *current_interface;
    uint32_t target_IPA;
    printf("GOT ARP REPLY HURRAY YO ! \n\n\n\n\n\n\n\n");
    /* make the ARP header struct and skip the Etherenet header details*/
    ARP_header = (sr_arp_hdr_t *) (packet + SR_ETH_HDR_LEN);

    /* fetch the target IP Address */
    target_IPA = ntohl(ARP_header->ar_tip);

    /* check if the ARP's target IP address is one of your router's IP addresses. */
    current_interface = sr->if_list;
    while (current_interface) {

        if (target_IPA == ntohl(current_interface->ip)) {

            /* store the ARP reply in the cache */
            printf("Inserting into cache.\n");
            struct sr_arpreq * to_cache = sr_arpcache_insert(&sr->cache,ARP_header->ar_sha, ARP_header->ar_sip);

            if(to_cache) {
            	send_waiting_packets(sr, to_cache);
            	printf("packets sent off\n");
            	sr_arpreq_destroy(&sr->cache, to_cache);
            }
          break;
        }
        current_interface = current_interface->next;
    }
}
