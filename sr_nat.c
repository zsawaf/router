
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>


/* HELPER FUNCTIONS FOR router.c */
struct sr_nat_connection *find_connection(struct sr_nat_connection *con, struct sr_nat_connection *target){

  uint16_t external_port = target->external_port;
  uint32_t external_ip = target->external_port;
  int found = 0;
  struct sr_nat_connection *copy = con;
  while(copy && (found == 0)) {
    if(copy->external_ip == external_ip && copy->external_port == external_port) {
      found = 1;
    }
    copy = copy->next;
  }
  return copy; 
}

struct sr_nat_mapping *find_mapping(struct sr_nat *nat, struct sr_nat_mapping *target) {
  struct sr_nat_mapping *entry = nat->mappings;
  int found = 0;
  while(entry && (found == 0)){
    if (target->ip_int == entry->ip_int && target->aux_int == entry->aux_int && target->aux_ext == entry->aux_ext
      && target->type == entry->type) {

      found = 1;
    }
    entry = entry->next;
  }
  return entry;
}

/* Functions used in router.c for inbound & outbound */

struct sr_nat_connection *sr_insert_connection(struct sr_nat *nat, 
  struct sr_nat_mapping *entry, struct sr_nat_connection *target) {

  pthread_mutex_lock(&(nat->lock));

  uint16_t external_port = target->external_port;
  uint32_t external_ip = target->external_ip;

  struct sr_nat_connection *con = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
  struct sr_nat_mapping *cur_entry = find_mapping(nat, entry);

  if(cur_entry) {
    struct sr_nat_connection *cur_conn = find_connection(cur_entry->conns, target);
    if (!cur_conn) {
      cur_conn = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
      cur_conn->stamp = time(NULL);
      cur_conn->external_ip = external_ip;
      cur_conn->external_port = external_port;
      cur_conn->state = STATE_INIT;
      cur_conn->sent = SYN_UNDEFINED;
      cur_conn->received = SYN_UNDEFINED;
      cur_conn->next = cur_entry->conns;
      cur_entry->conns = cur_conn;
    }

    memcpy(con, cur_conn, sizeof(struct sr_nat_connection));

    /* DROP THE MATCHING UNSOLICITED */
  }

  pthread_mutex_unlock(&(nat->lock));
  return con;
}

struct sr_nat_connection * sr_lookup_connection(struct sr_nat *nat, struct sr_nat_mapping *entry,
  struct sr_nat_connection *target) {

    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_connection *con = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
    struct sr_nat_mapping *cur_entry = find_mapping(nat, entry);
    struct sr_nat_connection *cur_conn = find_connection(cur_entry->conns, target);
    if (cur_entry && cur_conn) {
      memcpy(con, cur_conn, sizeof(struct sr_nat_connection));
    }

    pthread_mutex_unlock(&(nat->lock));
    return con;
}

/* Return 0 if tcp can be forwarded, 1 otherwise */
unsigned int forward_tcp_checker(struct sr_nat *nat, struct sr_nat_mapping *entry, struct sr_nat_connection *con, 
  int state, int direction){

  pthread_mutex_lock(&(nat->lock));

  uint8_t syn;
  uint8_t ack;
  uint8_t reset;
  uint8_t finish;
  int can_send;

  /* Check if entry is in mapping table, if it isn't we cannot forward the tcp */
  struct sr_nat_mapping *cur_entry = find_mapping(nat, entry);

  if (!cur_entry) {
    can_send = 0;
    pthread_mutex_unlock(&(nat->lock));
    return can_send;
  }

  /* Now we do the same for connection */
  struct sr_nat_connection *cur_con = find_connection(cur_entry->conns, con);
  if(!cur_con) {
    can_send = 0;
    pthread_mutex_unlock(&(nat->lock));
    return can_send;
  }

  syn = sr_tcp_hdr->offset & TCP_SYN;
  ack = sr_tcp_hdr->offset & TCP_ACK;
  reset = sr_tcp_hdr->offset & TCP_RST;
  finish = sr_tcp_hdr->offset & TCP_FIN;

  if (cur_con->state == STATE_INIT) {
    /* handle inbound */
    if(direction == OUTBOUND) {
      if(ack && cur_con->sent != SYN_ACK) {
        cur_con->sent = SYN_DEFINED;
        /* the sequence number thingy */
      }
    }
    else if(direction == INBOUND) {
      // might need to check for sent syn number as well
      if(cur->sent && ack == SYN_DEFINED && ntohl(sr_tcp_hdr->ack)) {
        cur_con->sent = SYN_ACK;
      }
      if(cur_con->received && syn != SYN_ACK) {
        cur_con->received = SYN_DEFINED;
        /* set sequence number tcp recieved*/
      }
    }
  }

  pthread_mutex_unlock(&(nat->lock));

  return 0;
}

/* HELPER FUNCTIONS FOR sr_nat.c */

void timeout_tcp_connections(struct sr_nat *nat, struct sr_nat_mapping *TCP_entry, time_t now) {
  double time_difference;
  double timeout;
  /* iterate over connections and delete the ones that are timed out */
  struct sr_nat_connection *entry = TCP_entry->conns;
  struct sr_nat_connection *previous_entry = NULL;

  while (entry) {
    time_difference = difftime(now, entry->stamp);

    /* Set connection timeout based on state */
    if (entry->state == STATE_INIT || entry->state == STATE_END) {
      timeout = SOME_OTHER_TIMEOUT;
    }
    else { /* connection is established */
      timeout = SOME_OTHER_OTHER_TIMEOUT;
    }

    if (time_difference > timeout) {
    /* remove from the middle of linked list */
      if (previous_entry) {
        previous_entry->next = entry->next;
        free(entry);
        entry = entry->next;
      }
      /* make the next entry the new LL head */
      else {
        TCP_entry->conns = entry->next;
        free(entry);
        entry = TCP_entry->conns;
      }
    }
  } 
}

int perform_type_action(struct sr_nat *nat, time_t now, struct sr_nat_mapping *entry) {
  int waiting_connections = 0;
  /* type-specific actions */
  if (entry->type == nat_mapping_tcp) {
    timeout_tcp_connections(nat, entry, now);
    if (entry->conns) {
      waiting_connections = 1;
    }
  }
  else if (entry->type == nat_unsolicited_packet) {
    /* send destination unreachable to host */
    printf("Send destination unreachable\n");
  }
  return waiting_connections;
}

/* When an unsolicited SYN is timed out, then we want to drop it
 * from the Linked List */
void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  double time_difference;

  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t now = time(NULL);
    int waiting_connections;

    /* iterate through the mappings and remove the timed out ones */
    struct sr_nat_mapping *entry = nat->mappings;
    struct sr_nat_mapping *previous_entry = NULL;

    while (entry) {
      time_difference = difftime(now, entry->last_updated);

      /* type-specific actions and find out if any connections waiting on this entry (if TCP) */
      waiting_connections = perform_type_action(nat, now, entry);

      /* linked-list-specific actions */
      if (time_difference > SR_NAT_TIMEOUT && !waiting_connections) { /* must put this var in .h file */
        /* remove from the middle of linked list */
        if (previous_entry) {
          previous_entry->next = entry->next;
          free(entry);
          entry = entry->next;
        }
        /* make the next entry the new LL head */
        else {
          nat->mappings = entry->next;
          free(entry);
          entry = nat->mappings;
        }
      }
      else {
        /* proceed to the next entry */
        previous_entry = entry;
        entry = entry->next;
      }
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Return a free port for the entry to use before being inserted to 
 * the mapping table */
uint16_t fetch_port(struct sr_nat *nat, sr_nat_mapping_type type) {

  struct sr_nat_mapping *entry = nat->mappings;
  uint16_t external_port;
  
  /* Check if the type is ICMP or TCP and assign the port number 
   * respectively */
  if (type == nat_mapping_tcp) {
    external_port = nat->tcp_port;
  }
  else {
    /* ICMP */
    external_port = nat->icmp_port;
  }

  /* Handle case where the port is 0 */
  if (external_port == 0) {
    if (type == nat_mapping_tcp) {
      external_port = TCP_PORT;
    }
    else {
      /* ICMP */
      external_port = ICMP_PORT;
    }
    while (entry) {
      if ((entry->aux_ext == htons(external_port)) && entry->type == type) {
        /* we need to increment the port number since the port is taken */
        external_port++;
        /* We need to restart and find another free port. */
        entry = nat->mappings;
      }
      else {
        entry = entry->next;
      }
    }
  }
  else {
    /* We can just increment the port number */
    if (type == nat_mapping_tcp) {
      nat->tcp_port++;
    }
    else {
      /* ICMP */
      nat->icmp_port++;
    }
  }
  return htons(external_port);
}


int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  /* initialize nat struct */

  nat->mappings = NULL;
  
  nat->ip_external = 0; /* set external port to 0 */
  nat->tcp_port = TCP_PORT; /* port 1024 reserved */
  nat->icmp_port = ICMP_PORT;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL, *entry = nat->mappings;

  int found = 0;

  /* iterate over entries until found matching type and external port */
  while(entry && (found==0)) {
    if ( (entry->aux_ext == aux_ext) && (entry->type == type)) {
        found = 1;
    }
    else {
      entry = entry->next;
    }
  }

  if (found == 1) {
    entry->last_updated = time(NULL);
    copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, entry, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL, *entry = nat->mappings;

  int found = 0;

  /* iterate over entries until found matching type, internal port and internal IP */
  while(entry && (found==0)) {
    if ( (entry->aux_int == aux_int) && (entry->type == type) && (entry->ip_int == ip_int)) {
        found = 1;
    }
    else {
      entry = entry->next;
    }
  }

  if (found == 1) {
    entry->last_updated = time(NULL);
    copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, entry, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
*/
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));

  /* initialize the new entry*/
  struct sr_nat_mapping *entry = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
  entry->type = type;
  entry->ip_int = ip_int;
  entry->aux_int = aux_int;
  entry->last_updated = time(NULL);
  entry->conns = NULL;
  entry->next = nat->mappings; /* insert it at the head like arpcache */

  entry->ip_ext = nat->ip_external; /* always going to be the same for this NAT (that's the pont!)*/
  entry->aux_ext = fetch_port(nat, type); 

  nat->mappings = entry; /*update linked list */

  memcpy(copy, entry, sizeof(struct sr_nat_mapping));
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}
