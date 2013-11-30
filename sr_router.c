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

#include <stdio.h>
#include <assert.h>

#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"




static const uint8_t ARP_MAC_BROADCAST [ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
#define SR_ARP_MAXSEND 5.0
#define SR_ARP_MAXDIF 1.0
static const char *internal_interface = "eth1";
static const char *external_interface = "eth2";
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here!*/ 
   

   /*NAT initialization*/
    if(sr->nat_active) 
      sr_nat_init(&(sr->nat));
   

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
  /*Setup NAT interfaces*/
  if(sr->nat_active==1 && (sr->nat.internal || sr->nat.external))
  {
    sr->nat.internal = sr_get_interface(sr,internal_interface);
    
    sr->nat.external = sr_get_interface(sr,external_interface);
    sr->nat.ip_external = sr->nat.external->ip;
  }
  
/*  printf("*** -> Received packet of length %d \n",len);
*/  print_hdrs(packet,len);
  /* fill in code here */
  /*Check that the packet is valid | Drop it otherwise*/
  unsigned int check_length = check_len(packet, len);
 
  if (check_length == 1){
    printf("\n*** ->Checking length is  successful\n");
  }
  else {
    printf("\n*** ->Failed checking length\n");
    return;
  }
 
  unsigned int check_sum = check_check_sum(packet);
 
  if (check_sum == 1){
    printf("\n*** ->Checking sum is  successful\n");
  }
  else {
    printf("\n*** ->Failed checking sum\n");
    return;
  }  

  /*GET THE PROTOCOL OF THE ETHERNET PACKET*/
  uint16_t ethprotocol = ntohs(((sr_ethernet_hdr_t*)packet)->ether_type);
  
  printf("-----\nProtocol : 0x%04x\n",ethprotocol);

  if(ethprotocol == ethertype_arp){
    printf("Packet protocol is ARP\n-----\n");
    /*Handle ARP PACKET*/
    handle_arp(sr,packet);
  }
  else
    if(ethprotocol == ethertype_ip)
      {printf("Packet protocol is IP\n-----\n");
  if(sr->nat_active==1){
    handle_nat_ip(sr,packet,len,sr_get_interface(sr,interface));
  }
  else
  handle_ip(sr,packet,len);
      }
}
void handle_nat_outbound(struct sr_instance* sr,uint8_t * packet,unsigned int len,struct sr_if* rec_interface)
{
  sr_ip_hdr_t* ipPacket = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
  uint8_t protocol = ipPacket -> ip_p;
  if(protocol==ip_protocol_icmp)
  {
    sr_echo_icmp_hdr_t* icmpPacket = (sr_echo_icmp_hdr_t*) (packet + sizeof(sr_ip_hdr_t)  + sizeof(sr_ethernet_hdr_t));
    
    struct sr_nat_mapping* mapping = sr_nat_lookup_internal(&(sr->nat),ipPacket->ip_src,icmpPacket->icmp_id,nat_mapping_icmp);
    if(!mapping)
    {
      mapping = sr_nat_insert_mapping(&(sr->nat),ipPacket->ip_src,icmpPacket->icmp_id,nat_mapping_icmp);
    }
    
    icmpPacket->icmp_id = mapping->aux_ext;
    icmpPacket->icmp_sum = 0;
    icmpPacket->icmp_sum = cksum(icmpPacket,len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
    
    ipPacket->ip_src=mapping->ip_ext;
    
    handle_ip(sr,packet,len);
    
  }
  else
    if(protocol==0x0006)
    {
      sr_tcp_hdr_t* tcpPacket = (sr_tcp_hdr_t*) (packet + sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t));
      printf("\n\nHEEEEERREEEx@31412412312412xxxn\n\n");
      struct sr_nat_mapping* mapping = sr_nat_lookup_internal(&(sr->nat),ipPacket->ip_src,tcpPacket->src_port,nat_mapping_tcp);
    printf("\n\nHEEEEERREEExxxxxxn\n\n");
    if(!mapping)
    {printf("\n\nHEEEEERREEE11zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz1n\n\n");
      if(tcpPacket->ctrl & TCP_SYN)
      mapping = sr_nat_insert_mapping(&(sr->nat),ipPacket->ip_src,tcpPacket->src_port,nat_mapping_tcp);
      else
        return;
    }printf("\n\nHEEEEERREEE111n\n\n");
    struct sr_nat_connection *connection = sr_lookup_connection(&(sr->nat),mapping,tcpPacket->dst_port,ipPacket->ip_dst);
    printf("\n\nHEEEEERREEE2222n\n\n");
    if (!connection) {
      if (tcpPacket->ctrl & TCP_SYN) {
        printf("@@@@@\"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@224214");
        connection = sr_insert_connection(&(sr->nat), mapping, tcpPacket->dst_port, ipPacket->ip_dst);
      }
      else
        return;
      }
       if(connection)
        printf("Connection not null \n\n\n\n\n\n");
        else
        printf("Connection is null \n\n\n\n\n\n");
      printf("\n\nHEEEEERREEEn\n\n");
      if (forward_tcp_checker(&(sr->nat), mapping, connection, tcpPacket, OUT) == 1)
      {printf("\n\nHEEEEERREEE$$$$$$4$$n\n\n");
        printf("\n\n@@@@tcpControl is : %i sequence is : %i ack is : %i \n\n\n",tcpPacket->ctrl & TCP_SYN,tcpPacket->seq,ntohs(tcpPacket->ack));
        print_hdr_tcp((uint8_t*)tcpPacket);
        tcpPacket->src_port = mapping->aux_ext;
        ipPacket->ip_src = mapping->ip_ext;
        tcpPacket->sum = 0; 
        tcpPacket->sum = tcpcksum(ipPacket, (uint8_t*)tcpPacket, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
        handle_ip(sr, packet, len);
      }
    }

}
uint16_t tcpcksum(sr_ip_hdr_t *ipPacket, uint8_t *tcpPacket, unsigned int len) {

  unsigned int fulllen = sizeof(sr_tcp_cksum_hdr_t) + len;
  uint8_t *pseudo = (uint8_t *)malloc(fulllen);

  sr_tcp_cksum_hdr_t *tcp_cksum_hdr = (sr_tcp_cksum_hdr_t *)pseudo;

  tcp_cksum_hdr->ip_src = ipPacket->ip_src;
  tcp_cksum_hdr->ip_dst = ipPacket->ip_dst;
  tcp_cksum_hdr->ip_p = ipPacket->ip_p;
  tcp_cksum_hdr->len = htons(len);
  memcpy(pseudo + sizeof(sr_tcp_cksum_hdr_t), tcpPacket, len);

  uint16_t checksum = cksum(pseudo, fulllen);
  return checksum;
}
void handle_nat_inbound(struct sr_instance* sr,uint8_t * packet,unsigned int len,struct sr_if* rec_interface)
{
  sr_ip_hdr_t* ipPacket = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
  uint8_t protocol = ipPacket -> ip_p;
  if(protocol==ip_protocol_icmp)
  {
    sr_echo_icmp_hdr_t* icmpPacket = (sr_echo_icmp_hdr_t*) (packet + sizeof(sr_ip_hdr_t)  + sizeof(sr_ethernet_hdr_t));
    
    struct sr_nat_mapping* mapping = sr_nat_lookup_external(&(sr->nat),icmpPacket->icmp_id,nat_mapping_icmp);
    if(!mapping)
    {
      return;
    }
    
    icmpPacket->icmp_id = mapping->aux_int;
    icmpPacket->icmp_sum = 0;
    icmpPacket->icmp_sum = cksum(icmpPacket,len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
    
    ipPacket->ip_dst=mapping->ip_int;
    
    handle_ip(sr,packet,len);
    
  }
  else
    if(protocol==0x0006)
    {
      sr_tcp_hdr_t* tcpPacket = (sr_tcp_hdr_t*) (packet + sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t));
      struct sr_nat_mapping* mapping = sr_nat_lookup_external(&(sr->nat),tcpPacket->dst_port,nat_mapping_tcp);
    if(!mapping)
    {
      if(tcpPacket->ctrl & TCP_SYN)
      mapping = sr_nat_insert_mapping(&(sr->nat),ipPacket->ip_src,tcpPacket->src_port,nat_mapping_tcp);
      else
        return;
    }
    struct sr_nat_connection *connection = sr_lookup_connection(&(sr->nat),mapping,tcpPacket->src_port,ipPacket->ip_src);
    if (!connection) {
      if (tcpPacket->ctrl & TCP_SYN) {
        connection = sr_insert_connection(&(sr->nat), mapping, tcpPacket->src_port, ipPacket->ip_src);
      }
      else
        return;
      }
      if(connection)
        printf("Connection not null \n\n\n\n\n\n");
        else
        printf("Connection is null \n\n\n\n\n\n");

      if (forward_tcp_checker(&(sr->nat), mapping, connection, tcpPacket, OUT) == 1)
      {
        printf("\n\n@@@@tcpControl is : %i sequence is : %i ack is : %i \n\n\n",tcpPacket->ctrl,tcpPacket->seq,ntohs(tcpPacket->ack));
        print_hdr_tcp((uint8_t*)tcpPacket);
        tcpPacket->dst_port = mapping->aux_int;
        ipPacket->ip_dst = mapping->ip_int;
        tcpPacket->sum = 0; 
        tcpPacket->sum = tcpcksum(ipPacket, (uint8_t*)tcpPacket, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
        printf("\n\n\n\n@@@@@@@@@HANDLE2222222 TCP INBOUND !!!!!!!!!!\n\n\n\n");
        handle_ip(sr, packet, len);
      }
    }

}

void handle_nat_ip(struct sr_instance* sr,uint8_t * packet,unsigned int len,struct sr_if* rec_interface)
{
  sr_ip_hdr_t* ipPacket = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
  uint8_t protocol = ipPacket -> ip_p;
  struct sr_if* interface = findInterface(ntohl(ipPacket->ip_dst),sr);
  if(interface)
  {
    printf("@@@@@Packet for interface");
    
      if(rec_interface == sr->nat.external && interface == sr->nat.internal)
      {
        /*Drop external packets for internal interface*/
        return;
      }

      if(protocol == ip_protocol_icmp)
      {
        sr_icmp_hdr_t* icmpPacket = (sr_icmp_hdr_t*) (packet + sizeof(sr_ip_hdr_t)  + sizeof(sr_ethernet_hdr_t));
        printf("ICMP Data\n\t TYPE:%d | CODE:%d | SUM:%d\n",icmpPacket->icmp_type,icmpPacket->icmp_code,icmpPacket->icmp_sum);
      
        if(icmpPacket->icmp_type==8 && icmpPacket->icmp_code==0)
        {/*Reply to echo*/
        send_echo_reply(sr,ipPacket->ip_src,ipPacket->ip_dst,icmpPacket,len);
        }
      
        else
          if(icmpPacket->icmp_type==0 && rec_interface == sr->nat.external && interface == sr->nat.external)
          {
            handle_nat_inbound(sr,packet,len,interface);
          }
      }
      else
        if(protocol == 0x0006 && interface == sr->nat.external)
        {
          printf("\n\n\n\n@@@@@@@@@HANDLE TCP INBOUND !!!!!!!!!!\n\n\n\n");
          handle_nat_inbound(sr,packet,len,interface);
        }
      else
        if(protocol==0x0006 || protocol==0x0011)
        {
          send_icmp(sr,ipPacket->ip_src,packet,3,3);
        }
      else
        {
          return;
        }
    
  } 
  else
  {
    printf("@@@@@Packet not for interface");
    if(protocol == ip_protocol_icmp)
    {
      sr_icmp_hdr_t* icmpPacket = (sr_icmp_hdr_t*) (packet + sizeof(sr_ip_hdr_t)  + sizeof(sr_ethernet_hdr_t));
      printf("ICMP Data\n\t TYPE:%d | CODE:%d | SUM:%d\n",icmpPacket->icmp_type,icmpPacket->icmp_code,icmpPacket->icmp_sum);
      
      if(icmpPacket->icmp_type!=8)
        return;
    }
    else
      if(protocol!=0x0006)
        return;
      printf("@@@@@geasgdikasdlgkaj\n");
    struct sr_rt* next_hop = longest_prefix_match(sr,ipPacket->ip_dst);
      printf("@@@@@@@some shiiiit\n");
    if(!next_hop->interface)
    {
      /*If to match was found send ICMP type : 3 code : 0 */
      printf("Failed to find the next hop | Send ICMP 3 Code 0 to Source\n");
      /*send_icmp(sr,ipPacket->ip_src,packet,3,0);*/
      return;
    }

    if(sr_get_interface(sr,next_hop->interface) == sr->nat.external)
    { 
      printf("@@@@!!!!!!!!!need to handle outbound\n");
      handle_nat_outbound(sr,packet,len,interface);
    } 
    
  }

  
}
void send_echo_reply(struct sr_instance* sr,uint32_t destination_ip,uint32_t sender_ip,sr_icmp_hdr_t* icmpPacket,unsigned int len)
{
  uint8_t * reply = (uint8_t*) malloc(len);
  /*ICMP DATALOAD*/
  int datalength = len - sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t)-sizeof(sr_icmp_hdr_t);
  /*IP DATALOAD = ICMP HEADER + ICMP DATA*/
  int ipTotalLength = datalength+sizeof(sr_icmp_hdr_t);
  
  sr_ip_hdr_t* ipheader = (sr_ip_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t));
  /*Create the IP header*/
  create_ip_header(ipheader,destination_ip,ipTotalLength,sender_ip);
  
  sr_icmp_hdr_t* icmp_packet = (sr_icmp_hdr_t *)(reply+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
  /*Copy the PING so we can send the PONG*/
  memcpy(icmp_packet,icmpPacket,sizeof(sr_icmp_hdr_t)+datalength);
 
  icmp_packet->icmp_type=0;
  icmp_packet->icmp_sum=0;
  icmp_packet->icmp_sum=cksum(icmp_packet,sizeof(sr_icmp_hdr_t));
  
  printf("Trying to send the echo reply\n");
  
  ethernet_with_arp(sr,reply,len);
}

void ethernet_with_arp(struct sr_instance* sr,uint8_t* packet,unsigned int len)
{ printf("2@@@%i",check_check_sum(packet));printf("boooomm\n");
  /*We only use this function for to send IP packets*/
  sr_ip_hdr_t* ipPacket = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
  /*Figure out the next hop using longest prefix match*/
  struct sr_rt* next_hop = longest_prefix_match(sr,ipPacket->ip_dst);
      
      if(next_hop==0)
  {
    /*If to match was found send ICMP type : 3 code : 0 */
  printf("Failed to find the next hop | Send ICMP 3 Code 0 to Source\n");
  send_icmp(sr,ipPacket->ip_src,packet,3,0);
  
    
  }
      else 
 
       {
   /*Find the next interface based on the routing table entry*/
   struct sr_if* next_interface = sr_get_interface(sr,next_hop->interface);
   
   printf("\nNeed to forward on Interface %s to ip\n\t",next_interface->name);/*print_addr_ip(next_hop->dest);*/
   print_addr_ip_int(ntohl(next_hop->dest.s_addr));printf("\n");
   
   /*Check the ARP cache for MAC addresss*/
   struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache,next_hop->dest.s_addr);
  
   if(entry)
     {printf("Found ARP entry\n");
       /*If found send the message*/
       create_ethernet_header(packet,entry->mac,next_interface->addr,ethertype_ip);
       int sent = sr_send_packet(sr,packet,len,next_interface->name);
       if(sent==0)
         {printf("Packet sent\n");
     print_hdrs(packet,len);}
       else
         {printf("Packet not sent, an error occured\n");}
     }
   else
     {
       printf("No entry found in the ARP Cache\n\tNeed to send ARP request");
      
       /* Queue the packet and send it when an ARP reply arrives */
       struct sr_arpreq *arp_request ;
       arp_request = sr_arpcache_queuereq(&sr->cache, next_hop->dest.s_addr, packet,len,next_interface->name);
       
     }




       }
}
void send_icmp(struct sr_instance* sr,uint32_t destination_ip,uint8_t * packet,unsigned int type,unsigned int code)
{ /*We use this function for ICMP type 3 and 11 as they have the same strucuture*/
  uint8_t * reply = (uint8_t*) malloc( sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
  /*The IP dataload is the ICMP data*/
  int ipDataLength = sizeof(sr_icmp_t3_hdr_t);
  
  sr_ip_hdr_t* ipheader = (sr_ip_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t));
  create_ip_header(ipheader,destination_ip,ipDataLength,sr->if_list->ip);/*DOES NOT MATTER FROM WHICH INTERFACE WE SEND IT*/
  
  sr_ip_hdr_t* packet_ipheader = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  uint8_t* packet_data = packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);

  sr_icmp_t3_hdr_t* icmp_packet = (sr_icmp_t3_hdr_t *)(reply+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
  icmp_packet->icmp_type=type;
  icmp_packet->icmp_code=code;
  icmp_packet->icmp_sum=0;
  /*Copy the failed packet IP header and 64 first bits into the data field of ICMP*/
  memcpy(icmp_packet->data,packet_ipheader,sizeof(sr_ip_hdr_t));
  memcpy((icmp_packet->data)+sizeof(sr_ip_hdr_t),packet_data,8);
  
  icmp_packet->icmp_sum=cksum(icmp_packet,sizeof(sr_icmp_t3_hdr_t));
  
  printf("Trying to send the ICMP \n\tType:%i\n\tCode: %i\n",type,code);
  /*Find the MAC and send*/
  ethernet_with_arp(sr,reply,sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
}
void create_ip_header(sr_ip_hdr_t* packet,uint32_t dest_ip,int datalen,uint32_t sender_ip)
{/*Creates the IP header for ICMP messages*/
  packet->ip_v =4;
  packet->ip_hl=5;
  packet->ip_tos = 0;
  packet->ip_len = htons(sizeof(sr_ip_hdr_t)+datalen);
  packet->ip_id = 0;
  packet->ip_off = 0;
  packet->ip_ttl = 64;
  packet->ip_p = 1;
  packet->ip_src = sender_ip;
  packet->ip_dst = dest_ip;
  packet->ip_sum=0;
  packet->ip_sum = cksum(packet,sizeof(sr_ip_hdr_t));
}


struct sr_rt* longest_prefix_match(struct sr_instance* sr,uint32_t ip)
{
    struct sr_rt * curr_rt = sr->routing_table;
    struct sr_rt * res_rt = NULL;
    uint32_t subnetwork;
    int i=0;
    /* Iterate through curr_rt's linked list and find the best match */
    while(curr_rt){
     
      subnetwork = curr_rt->dest.s_addr & curr_rt->mask.s_addr;
     
      /* Now we do the IP match up */
      if (subnetwork == (ip & curr_rt->mask.s_addr)){
        printf("IP match found!\n");
          /* fill out first time */
          if(!res_rt){
      res_rt = curr_rt;
            }
            else{
        printf("Routing table isn't empty.\n");
              if(ntohl(res_rt->mask.s_addr) < ntohl(curr_rt->mask.s_addr))
    {
                 printf("Found a better match");
     res_rt = curr_rt;
                }
            }
        }
        curr_rt = curr_rt->next;
        i++;
    }
    printf("!!!!!!!!!!!!!!!!!!!@@@@@gets out");
    return res_rt;
}

void handle_ip(struct sr_instance* sr,uint8_t * packet,unsigned int len)
{
  sr_ip_hdr_t* ipPacket = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
  uint8_t protocol = ipPacket -> ip_p;
  struct sr_if* interface = findInterface(ntohl(ipPacket->ip_dst),sr); 
  printf("---------------------------------\n");
  if(interface)
    {/*Handle IP packet for router*/
      printf("IP packet for interface\n");
       printf("Protocol is %d\n",protocol);
       if(protocol==ip_protocol_icmp)
   {
      /*Handle ICMP packet*/
      printf("ICMP Packet\n");
      sr_icmp_hdr_t* icmpPacket = (sr_icmp_hdr_t*) (packet + sizeof(sr_ip_hdr_t)  + sizeof(sr_ethernet_hdr_t));
      printf("ICMP Data\n\t TYPE:%d | CODE:%d | SUM:%d\n",icmpPacket->icmp_type,icmpPacket->icmp_code,icmpPacket->icmp_sum);
      
      if(icmpPacket->icmp_type==8 && icmpPacket->icmp_code==0)
  {/*Reply to echo*/
    send_echo_reply(sr,ipPacket->ip_src,ipPacket->ip_dst,icmpPacket,len);
  }
   }
       else
   {
     /*Not ICMP  packet*/
     printf("Not ICMP Packet\n ");
     /*Check if protocol is TCP or UDP*/
       if(protocol==0x0006 || protocol==0x0011)
         {
     send_icmp(sr,ipPacket->ip_src,packet,3,3);
         }
       else
         {
     return;
     /*Drop the packet in all other cases*/
     
         }
   }
    }
  else
    {/*Handle forwarding*/
      printf("IP packet not for interface | Need to forward packet\n");
      /*Need to decrement TTL and recompute the checksum | Send ICMP 11 if not valid*/
      if(ipPacket->ip_ttl == 0 || ipPacket->ip_ttl-1 == 0)
  {    
    printf("WARNING : TTL FOR THIS PACKET IS 0 OR 1\nSending ICMP message to source");
    send_icmp(sr,ipPacket->ip_src,packet,11,0);
  }
      else
  {/*Forward the packet if valid*/
    ipPacket->ip_ttl--;
    ipPacket->ip_sum=0;
    ipPacket->ip_sum=cksum(ipPacket,sizeof(sr_ip_hdr_t));
    ethernet_with_arp(sr,packet,len);
  }
    
    }

  printf("---------------------------------\n");
  
}
void handle_arp(struct sr_instance* sr,uint8_t * packet)
{
  sr_arp_hdr_t* arpPacket = (sr_arp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));   
  uint32_t tip = ntohl(arpPacket -> ar_tip); print_addr_ip_int(tip);
  
  unsigned short arp_type = ntohs(arpPacket -> ar_op); 
  printf("Operation is %d\n",arp_type);
  struct sr_if* interface = findInterface(tip,sr);
  printf("---------------------------------\n");
  /*Check if it matches any interface*/
  if(interface)
    {
      printf("Request matches Interface\n");
      if(arp_type==1)
  {/*Send a reply*/
    uint8_t * reply = generate_arp_reply(arpPacket,interface->ip,interface->addr);
   
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
      {/*Handle reply*/
  handle_reply(sr, packet);
      }
      else
        printf("Invalid operation type");
    }
  else
    {/*Drop it | We do not handle ARP messages not for our interfaces*/
      return;
      printf("Does not match any interface | Ignore the packet");
    }
  printf("---------------------------------\n");
  
}
void create_ethernet_header(uint8_t* reply, const uint8_t* destination, const uint8_t* sender, uint16_t type)
{
  memcpy(((sr_ethernet_hdr_t*)reply)->ether_dhost, destination, ETHER_ADDR_LEN);
  memcpy(((sr_ethernet_hdr_t*)reply)->ether_shost, sender, ETHER_ADDR_LEN);
  ((sr_ethernet_hdr_t*)reply)->ether_type = htons(type);
}
/*Generate the ARP reply to one of our interfaces*/
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
/*Finds and interface based on destination IP*/
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

void generate_arp_request(struct sr_instance *sr, struct sr_arpreq *arpreq) {

 

    time_t now = time(NULL);
    time_t last_sent = arpreq->sent;

    if (difftime(now, last_sent) > SR_ARP_MAXDIF) {
        if (arpreq->times_sent >= SR_ARP_MAXSEND) {

    printf("Sent ARP 5 times | ICMP Destination Host Unreachable to Source\n");
      struct sr_packet *packet = arpreq->packets;
      while(packet)
        { 
    
    send_icmp(sr,((sr_ip_hdr_t*)((packet->buf)+sizeof(sr_ethernet_hdr_t)))->ip_src,packet->buf,3,1);
    packet = packet -> next;
        }
      sr_arpreq_destroy(&sr->cache, arpreq);
  }else{
    

        uint8_t * request = (uint8_t *) malloc(SR_ETH_HDR_LEN + SR_ARP_HDR_LEN);

        /* find out-going interface */
        struct sr_rt *routing_table = longest_prefix_match(sr, arpreq->ip);
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

  printf("\n\tSending ARP request # %i\n\n",arpreq->times_sent+1);
        sr_send_packet(sr, request, SR_ETH_HDR_LEN + SR_ARP_HDR_LEN, iface->name);

        /* update request information */
        arpreq->times_sent += 1; now = time(NULL);
        arpreq->sent = now;
        }
        }
}



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
    
    eth_hdr->ether_type =htons(ethertype_ip);
                printf("\tSending packet... \n");
    print_hdrs(packets->buf,packets->len);

    int sent = sr_send_packet(sr, packets->buf, packets->len, packets->iface);
      
    if(sent==0)
      {printf("Packet waiting in queue successfully sent\n");}
    else
      {printf("Packet waiting in queue not sent\n");}
            
    struct sr_packet *new_packet = packets->next;
    packets = new_packet;
        }
    }
}

void handle_reply(struct sr_instance* sr,uint8_t * packet) {

    /* initialize variables */
    sr_arp_hdr_t *ARP_header;
    struct sr_if *current_interface;
    uint32_t target_IPA;
    printf("Received ARP reply\n");
    /* make the ARP header struct and skip the Etherenet header details*/
    ARP_header = (sr_arp_hdr_t *) (packet + SR_ETH_HDR_LEN);

    /* fetch the target IP Address */
    target_IPA = ntohl(ARP_header->ar_tip);

    /* check if the ARP's target IP address is one of your router's IP addresses. */
    current_interface = sr->if_list;
    while (current_interface) {

        if (target_IPA == ntohl(current_interface->ip)) {

            /* store the ARP reply in the cache */
            printf("Inserting into cache\n");
            struct sr_arpreq * to_cache = sr_arpcache_insert(&sr->cache,ARP_header->ar_sha, ARP_header->ar_sip);

            if(to_cache) {
                    send_waiting_packets(sr, to_cache);
                    printf("Sent all waiting packets\n");
                    sr_arpreq_destroy(&sr->cache, to_cache);
            }
          break;
        }
        current_interface = current_interface->next;
    }
}
/* Switch function to get the correct ethertype size */
unsigned int ethertype_len(uint16_t ethertype){
  if(ethertype == ethertype_ip){
    return sizeof(sr_ip_hdr_t);
  }
  else if(ethertype == ethertype_arp){
    return sizeof(sr_arp_hdr_t);
  }
  else {
    return 0;
  }
}
 
/* Sanity check on length. Return 1 on success, 0 on failure. */
unsigned int check_len(uint8_t *packet, unsigned int len){
  
  unsigned int ethernet_hdr_len = sizeof(sr_ethernet_hdr_t);
 
  /* Check that the length is compatible */
  if (len < ethernet_hdr_len){
    printf("Ethernet header length incompatible size.\n");
    return 0;
  }
  
  /* Check sanity of protocol headers */
  uint16_t ethernet_protocol = ntohs(((sr_ethernet_hdr_t*)packet)->ether_type);
  unsigned int protocol_hdr_len = ethertype_len(ethernet_protocol);
  if (len < SR_ETH_HDR_LEN + protocol_hdr_len){
    printf("Protocol header length incompatible size.\n");
    return 0;
  }
 
  if (ethernet_protocol == ethertype_arp){
    sr_arp_hdr_t *arp_packet = (sr_arp_hdr_t *)(packet + SR_ETH_HDR_LEN);
    if (ntohs(arp_packet->ar_pro) != ethertype_ip){
      printf("Protocol data incompatible.");
      return 0;
    }
  }
  else if (ethernet_protocol == ethertype_ip){
    sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*)(packet + SR_ETH_HDR_LEN);
    if (len < SR_ETH_HDR_LEN + ntohs(ip_packet->ip_len)){
      return 0;
    }
  }
  else {
    printf("Ethernet Protocol %x is not recognized\n", ethernet_protocol);
  }
 
  return 1;
}
 
unsigned int check_check_sum(uint8_t *packet){
  uint16_t ethernet_protocol = ntohs(((sr_ethernet_hdr_t*)packet)->ether_type);
  if (ethernet_protocol == ethertype_ip){
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t*)(packet + SR_ETH_HDR_LEN);
    uint16_t ip_sum = ip_header->ip_sum;
    ip_header->ip_sum = 0;
    uint16_t ip_hdr_len = sizeof(sr_ip_hdr_t);
    uint16_t compute_sum = cksum(ip_header, ip_hdr_len);
    ip_header->ip_sum = ip_sum;
    unsigned int is_sane = (ip_sum == compute_sum);
    return is_sane;
  }
  return 1;
}