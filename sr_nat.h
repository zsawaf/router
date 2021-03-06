#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#define TCP_PORT 1024
#define ICMP_PORT 1
#define TIMEOUT 6
#define STATE_INIT 1
#define STATE_CONNECTED 2
#define STATE_END 3
#define SYN_UNDEFINED 1
#define SYN_DEFINED 2
#define SYN_ACK 3

#define IN 0 /* inbound */
#define OUT 1 /*outbound */

#define UNSOL_TIMEOUT 6
#define ICMP_TIMEOUT 60
#define TCP_ESTB_TIMEOUT 7440
#define TCP_TRAN_TIMEOUT 300

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_protocol.h"

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  time_t stamp;
  uint32_t external_ip;
  uint16_t external_port;
  unsigned int state;
  unsigned int sent;
  unsigned int received;
  uint32_t sequence_number_sent;
  uint32_t sequence_number_received;
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */

  struct sr_nat_mapping *next;
};

struct sr_nat_unsol_pack {
  time_t last_updated;
  uint32_t IP_src;
  uint16_t port_src;
  uint16_t port_dst;
  struct sr_nat_unsol_pack *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  struct sr_nat_unsol_pack *unsol_packs;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;

  /* extra added fields */
  struct sr_if* external;
  struct sr_if* internal;
  uint32_t ip_external;
  uint16_t icmp_port;
  uint16_t tcp_port;
};


int sr_nat_init(struct sr_nat *nat); /* Initializes the nat */
int sr_nat_destroy(struct sr_nat *nat); /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr); /* Periodic Timout */

/* Get the mapping associated with given external port.
You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );
struct sr_nat_connection * sr_lookup_connection(struct sr_nat *nat, struct sr_nat_mapping *entry,
  uint16_t external_port, uint32_t external_ip);
unsigned int forward_tcp_checker(struct sr_nat *nat, struct sr_nat_mapping *entry, struct sr_nat_connection *con,
  sr_tcp_hdr_t *tcp, int direction);
struct sr_nat_connection *sr_insert_connection(struct sr_nat *nat,
  struct sr_nat_mapping *entry, uint16_t external_port, uint32_t external_ip);
#endif