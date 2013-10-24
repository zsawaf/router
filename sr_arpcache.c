#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_if.h"
#include "sr_protocol.h"

static const uint8_t ARP_MAC_BROADCAST [ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/*
 * Handle the arp request, send request is necessary. 
 */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *arpreq) {

    time_t now = time(NULL); /* initialize current time */
    time_t sent = arpreq->sent; /* initialize time the req is sent. */ 
    if (difftime(now, sent) > SR_ARP_MAXDIF){
        if (arpreq->times_sent >= SR_ARP_MAXSEND){

            /*sr_send_unreachable(sr, arpreq);*/

            sr_arpreq_destroy(&sr->cache, arpreq);
        }
        else {
            sr_send_arpreq(sr, arpreq);
        }

    }
}

/*
* Return the longest prefix match for 'ip'
* in sr's routing table, if not found, return NULL.
*/
struct sr_rt * sr_search_ip_prfx(struct sr_instance * sr, uint32_t ip){
    struct sr_rt * curr_rt = sr->routing_table;
    struct sr_rt * res_rt = NULL;
    uint32_t subnetwork;

    /* Iterate through curr_rt's linked list and find the best match */
    while(curr_rt){
        subnetwork =  curr_rt->dest.s_addr & curr_rt->mask.s_addr;
        /* Now we do the IP match up */
        if (subnetwork == (ip & curr_rt->mask.s_addr)){
            /* fill out first time */
            if(!res_rt){
                res_rt = curr_rt;
            }
            else{
                if(ntohl(res_rt->mask.s_addr) < ntohl(curr_rt->mask.s_addr)) {
                    res_rt = curr_rt;
                }
            }
        }
        curr_rt = curr_rt->next;
    }
    return res_rt;
}

/*
* Populate request header, then send broadcast that shit.
*/
void sr_arp_broadcast(struct sr_instance *sr, struct sr_arpreq *arpreq){

    /* Set 'now' time */
    time_t now = time(NULL);

    /* Build up parameters for request */
    uint8_t *buf = (uint8_t *) malloc(SR_ETH_HDR_LEN + SR_ARP_HDR_LEN);

    /* build hdrs */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) buf;

    /* Move pointer forward SR_ETH_HDR bits */
    sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *) (buf + SR_ETH_HDR_LEN);

    /* We need to get the interface, therefore we need to do an IP lookup. */
    struct sr_rt *matched = sr_search_ip_prfx(sr, arpreq->ip);
    const char *name = matched->interface;
    struct sr_if *interface = sr_get_interface(sr, name);
    
    unsigned char * ifaceaddr = interface->addr;
    uint32_t ifaceip = interface->ip;

    /* make a new eth_hdr struct and populate */
    eth_hdr->ether_type = ethertype_arp;
    memcpy(eth_hdr->ether_dhost, ARP_MAC_BROADCAST, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, ifaceaddr, ETHER_ADDR_LEN);
    
    /* make an arp_hdr and populate */


    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ip_protocol_icmp); /*not sure*/
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4; /* change later lulz*/
    arp_hdr->ar_op = arp_op_request;
    memcpy(arp_hdr->ar_sha, ifaceaddr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = ifaceip;
    memcpy(arp_hdr->ar_tha, ARP_MAC_BROADCAST, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = arpreq->ip;

    /* SEND THE PACKET */
    sr_send_packet(sr, buf, (SR_ETH_HDR_LEN + SR_ARP_HDR_LEN), interface->name);

    free(buf);
    arpreq->sent = now;
    arpreq->times_sent++;
}

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    /* Key idea here is that we have to iterate through each request in arpreq struct 
     * and call arp_cache_handler on them. 
     */

     struct sr_arpreq *arpreq = sr->cache.requests;

     /*is not empty*/
     while(arpreq){ 
        handle_arpreq(sr, arpreq);
        arpreq = arpreq->next; /*get the next request*/
     }
}

/*
* Handle code where it sends unreachable. 
*/
void sr_send_unreachable(struct sr_instance *sr, struct sr_arpreq *arpreq){

}

/*
* Send that mofo
*/
void sr_send_arpreq(struct sr_instance *sr, struct sr_arpreq *arpreq){

    /*Do a cache look up. */
    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, arpreq->ip);
    if(entry){
        /*use next_hop_ip->mac mapping in entry to send the packet*/
        /* maybe we need to start with packets->next*/
        struct sr_packet *packets = arpreq->packets;
        while (packets){
            /* Send packet */
            sr_send_packet(sr, packets->buf, packets->len, packets->iface);

            /*Destroy and free the packet memory*/
            struct sr_packet *new_packet = packets->next;
            free(packets->buf);
            free(&packets->len);
            free(packets->iface);
            packets = new_packet;
        }
        /*free entry*/
    }
    else {
        /*arpreq = arpcache_queuereq(next_hop_ip, packet, len);*/
       
        handle_arpreq(sr, arpreq);
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

