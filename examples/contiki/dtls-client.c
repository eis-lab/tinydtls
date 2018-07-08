/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ip/resolv.h"
#include "dev/serial-line.h"
#include "tinydtls.h"

#include <string.h>
#include <stdbool.h>

#include "cfs-coffee.h"  //cfs test
//#include "codo/cfs-coffee-security.h" //cfs test

#ifndef DEBUG
#define DEBUG DEBUG_PRINT
#endif
#include "net/ip/uip-debug.h"
#include "alert.h"
#include "debug.h"
#include "dtls.h"
#include "sys/rtimer.h"
#define FILENAME "test"
#define FILENAME2 "test2"
#define payload 30
char cfs_buf[payload];
char read_buf[300];
char *filename;
int fd;
int iterator;
int data_len;
unsigned char iv[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
int j;
int packet_count = 27;
int it;
static int rtimer_count =0;
static int rtimer_count2 =0;
static int num = 2;
#define CFS_READ_MACRO(fd_read, read_buf, size) total = 0;                                                                                                                              \
                                                while (1) {                                                                                                                             \
                                                    n = cfs_read(fd_read, read_buf + total,size - total);                                                                               \
                                                    if(n == -1) {                                                                                                                       \
                                                            printf("reading - n = -1!\n");                                                                                              \
                                                            break;                                                                                                                      \
                                                    }                                                                                                                                   \
                                                    if ((n == size - total) || (n < (size- total) && cfs_security_errno == CFS_SECURITY_TRIMMED)) {                                     \
                                                        break;                                                                                                                          \
                                                    } else if (cfs_security_errno == CFS_SECURITY_KEYNEEDED) {                                                                          \
                                                        PROCESS_WAIT_EVENT();                                                                                                           \
                                                        if (ev == event_key_fetched)                                                                                                    \
                                           		{                                                                                                                               \
                                                            cfs_security_errno = CFS_SECURITY_INIT;                                                                                     \
                                                            if (n != -1)                                                                                                                \
                                                                total += n;                                                                                                             \
                                                        }                                                                                                                               \
                                                    } else {                                                                                                                            \
                                                        break;                                                                                                                          \
                                                    }                                                                                                                                   \



#ifdef DTLS_PSK
/* The PSK information for DTLS */
/* make sure that default identity and key fit into buffer, i.e.
 * sizeof(PSK_DEFAULT_IDENTITY) - 1 <= PSK_ID_MAXLEN and
 * sizeof(PSK_DEFAULT_KEY) - 1 <= PSK_MAXLEN
*/

#define PSK_ID_MAXLEN 32
#define PSK_MAXLEN 32
#define PSK_DEFAULT_IDENTITY "Client_identity"
#define PSK_DEFAULT_KEY      "secretPSK"
#endif /* DTLS_PSK */

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])


#define SEND_INTERVAL		10 * CLOCK_SECOND
#define MAX_PAYLOAD_LEN		120

static struct uip_udp_conn *client_conn;
static dtls_context_t *dtls_context;
static char buf[200];
static size_t buflen = 0;
static int connected = 0;
static const unsigned char ecdsa_priv_key[] = {
                        0x41, 0xC1, 0xCB, 0x6B, 0x51, 0x24, 0x7A, 0x14,
                        0x43, 0x21, 0x43, 0x5B, 0x7A, 0x80, 0xE7, 0x14,
                        0x89, 0x6A, 0x33, 0xBB, 0xAD, 0x72, 0x94, 0xCA,
                        0x40, 0x14, 0x55, 0xA1, 0x94, 0xA9, 0x49, 0xFA};

static const unsigned char ecdsa_pub_key_x[] = {
                        0x36, 0xDF, 0xE2, 0xC6, 0xF9, 0xF2, 0xED, 0x29,
                        0xDA, 0x0A, 0x9A, 0x8F, 0x62, 0x68, 0x4E, 0x91,
                        0x63, 0x75, 0xBA, 0x10, 0x30, 0x0C, 0x28, 0xC5,
                        0xE4, 0x7C, 0xFB, 0xF2, 0x5F, 0xA5, 0x8F, 0x52};

static const unsigned char ecdsa_pub_key_y[] = {
                        0x71, 0xA0, 0xD4, 0xFC, 0xDE, 0x1A, 0xB8, 0x78,
                        0x5A, 0x3C, 0x78, 0x69, 0x35, 0xA7, 0xCF, 0xAB,
                        0xE9, 0x3F, 0x98, 0x72, 0x09, 0xDA, 0xED, 0x0B,
                        0x4F, 0xAB, 0xC3, 0x6F, 0xC7, 0x72, 0xF8, 0x29};

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&resolv_process,&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
try_send(struct dtls_context_t *ctx, session_t *dst) {
  printf("try_send func!!\n");
  int res;
  res = dtls_write(ctx, dst, (uint8 *)buf, buflen);
  if (res >= 0) {
    memmove(buf, buf + res, buflen - res);
    buflen -= res;
  }
}

static int
read_from_peer(struct dtls_context_t *ctx,
               session_t *session, uint8 *data, size_t len) {
  size_t i;
  char sendbuf[250];
  printf("\n\nread_from_peer func!\nreceived packet: ");
  for (i = 0; i < len; i++)
    PRINTF("%c", data[i]);
  rtimer_count = rtimer_arch_now();
  int r = cfs_read(fd, &sendbuf, sizeof(sendbuf));

  if(r == 0) {
    printf("r is 0\n");
    cfs_close(fd);
    return 0;
  } else if(r < sizeof(sendbuf)) {
    printf("close cfs\n");
    cfs_close(fd);
    return 0;
  }
/*  static inline int dtls_int_to_uint16(unsigned char *field, uint16_t value)
{
  field[0] = (value >> 8) & 0xff;
  field[1] = value & 0xff;
  return 2;
}*/
  //dtls_debug_dump("sendbuf 1:", sendbuf, 21);
  //change_sequence(sendbuf,num);
  //num++;
  //dtls_record_header_t *header = DTLS_RECORD_HEADER(sendbuf);
  //dtls_int_to_uint8(sendbuf+10, 0x03);
  //dtls_debug_dump("sendbuf 2:", sendbuf, 21);
  //printf("cfs_Read res:%d\n",r);
  //rtimer_count2 = rtimer_arch_now() - rtimer_count;
  //printf("cfs_read rtimer_count:%d\n",rtimer_count2);

  //dtls_write(ctx,session,(uint8 *)sendbuf,sizeof(sendbuf));    //using unecrypted data
  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);

  uip_ipaddr_copy(&conn->ripaddr, &session->addr);

  conn->rport = UIP_HTONS(3000);

  uip_udp_packet_send(conn, sendbuf, sizeof(sendbuf));

  /* Restore server connection to allow data from any node */
  /* FIXME: do we want this at all? */
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  rtimer_count2 = rtimer_arch_now() - rtimer_count;
  printf("dtls_send rtimer_count:%d\n",rtimer_count2);
  return 0;
}

/*-----------------------------------------------------------*/
static char buf2[MAX_PAYLOAD_LEN];
static void
timeout_handler(void)
{
  static int seq_id;

  //printf("Client sending to: ");
  //PRINT6ADDR(&client_conn->ripaddr);
  sprintf(buf2, "Hello %d from the client", ++seq_id);
  //printf(" (msg: %s)\n", buf2);
#if SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION
  uip_udp_packet_send(client_conn, buf2, UIP_APPDATA_SIZE);
#else /* SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION */
  uip_udp_packet_send(client_conn, buf2, strlen(buf2));
#endif /* SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION */
}

/*-----------------------------------------------------------*/
static int
send_to_peer(struct dtls_context_t *ctx,
             session_t *session, uint8 *data, size_t len) {

  //rtimer_count2 = rtimer_arch_now() - rtimer_count;
  //printf("dtls_encrypt rtimer_count:%d\n",rtimer_count2);
  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);

  uip_ipaddr_copy(&conn->ripaddr, &session->addr);

  conn->rport = UIP_HTONS(3000);


  uip_udp_packet_send(conn, data, len);

  /* Restore server connection to allow data from any node */
  /* FIXME: do we want this at all? */
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  return len;
}
static int
cfs_save_dtls(struct dtls_context_t *ctx,
             session_t *session, uint8 *data, size_t len){

      int fd2 = cfs_open(FILENAME2,CFS_WRITE);
          if(fd >= 0){
            int res = cfs_write(fd2,data,len);
            printf("cfs_write_res: %d, len:%d\n",res,len);
          } else{
            printf("\ncfs_file_open error!\n");
          }
      cfs_close(fd2);
}
#ifdef DTLS_PSK
static unsigned char psk_id[PSK_ID_MAXLEN] = PSK_DEFAULT_IDENTITY;
static size_t psk_id_length = sizeof(PSK_DEFAULT_IDENTITY) - 1;
static unsigned char psk_key[PSK_MAXLEN] = PSK_DEFAULT_KEY;
static size_t psk_key_length = sizeof(PSK_DEFAULT_KEY) - 1;

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__((unused))
#else
#define UNUSED_PARAM
#endif /* __GNUC__ */

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx UNUSED_PARAM,
            const session_t *session UNUSED_PARAM,
            dtls_credentials_type_t type,
            const unsigned char *id, size_t id_len,
            unsigned char *result, size_t result_length) {

  switch (type) {
  case DTLS_PSK_IDENTITY:
    if (result_length < psk_id_length) {
      dtls_warn("cannot set psk_identity -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_id, psk_id_length);
    return psk_id_length;
  case DTLS_PSK_KEY:
    if (id_len != psk_id_length || memcmp(psk_id, id, id_len) != 0) {
      dtls_warn("PSK for unknown id requested, exiting\n");
      return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
    } else if (result_length < psk_key_length) {
      dtls_warn("cannot set psk -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_key, psk_key_length);
    return psk_key_length;
  default:
    dtls_warn("unsupported request type: %d\n", type);
  }
  return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
}
#endif

#ifdef DTLS_ECC
static int
get_ecdsa_key(struct dtls_context_t *ctx,
              const session_t *session,
              const dtls_ecdsa_key_t **result) {
  static const dtls_ecdsa_key_t ecdsa_key = {
    .curve = DTLS_ECDH_CURVE_SECP256R1,
    .priv_key = ecdsa_priv_key,
    .pub_key_x = ecdsa_pub_key_x,
    .pub_key_y = ecdsa_pub_key_y
  };

  *result = &ecdsa_key;
  return 0;
}

static int
verify_ecdsa_key(struct dtls_context_t *ctx,
                 const session_t *session,
                 const unsigned char *other_pub_x,
                 const unsigned char *other_pub_y,
                 size_t key_size) {
  return 0;
}
#endif /* DTLS_ECC */

/*---------------------------------------------------------------------------*/
static void
dtls_handle_read(dtls_context_t *ctx) {
  session_t session;
  memset(&session, 0, sizeof(session_t));
  PRINTF("dtls_handle_read!\n");
  if(uip_newdata()) {
    uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
    session.port = UIP_UDP_BUF->srcport;
    session.size = sizeof(session.addr) + sizeof(session.port);

    ((char *)uip_appdata)[uip_datalen()] = 0;
    PRINTF("Client received message from ");
    PRINT6ADDR(&session.addr);
    PRINTF(":%d\n", uip_ntohs(session.port));

    dtls_handle_message(ctx, &session, uip_appdata, uip_datalen());
  }
}
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Client IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
    }
  }
}
/*---------------------------------------------------------------------------*/
#if UIP_CONF_ROUTER
static void
set_global_address(void)
{
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
}
#endif /* UIP_CONF_ROUTER */
/*---------------------------------------------------------------------------*/
static resolv_status_t
set_connection_address(uip_ipaddr_t *ipaddr)
{
#ifndef UDP_CONNECTION_ADDR
#if RESOLV_CONF_SUPPORTS_MDNS
#define UDP_CONNECTION_ADDR       contiki-udp-server.local
#elif UIP_CONF_ROUTER
#define UDP_CONNECTION_ADDR       aaaa:0:0:0:0212:7404:0004:0404
#else
#define UDP_CONNECTION_ADDR       fe80:0:0:0:6466:6666:6666:6666
#endif
#endif /* !UDP_CONNECTION_ADDR */

#define _QUOTEME(x) #x
#define QUOTEME(x) _QUOTEME(x)

  resolv_status_t status = RESOLV_STATUS_ERROR;

  if(uiplib_ipaddrconv(QUOTEME(UDP_CONNECTION_ADDR), ipaddr) == 0) {
    uip_ipaddr_t *resolved_addr = NULL;
    status = resolv_lookup(QUOTEME(UDP_CONNECTION_ADDR),&resolved_addr);
    if(status == RESOLV_STATUS_UNCACHED || status == RESOLV_STATUS_EXPIRED) {
      PRINTF("Attempting to look up %s\n",QUOTEME(UDP_CONNECTION_ADDR));
      resolv_query(QUOTEME(UDP_CONNECTION_ADDR));
      status = RESOLV_STATUS_RESOLVING;
    } else if(status == RESOLV_STATUS_CACHED && resolved_addr != NULL) {
      PRINTF("Lookup of \"%s\" succeded!\n",QUOTEME(UDP_CONNECTION_ADDR));
    } else if(status == RESOLV_STATUS_RESOLVING) {
      PRINTF("Still looking up \"%s\"...\n",QUOTEME(UDP_CONNECTION_ADDR));
    } else {
      PRINTF("Lookup of \"%s\" failed. status = %d\n",QUOTEME(UDP_CONNECTION_ADDR),status);
    }
    if(resolved_addr)
      uip_ipaddr_copy(ipaddr, resolved_addr);
  } else {
    status = RESOLV_STATUS_CACHED;
  }

  return status;
}

void
cfs_prepare_data(struct dtls_context_t *ctx, session_t *session){

  char msg[payload];
  char sendbuf[250];
  int i;
  int fd = cfs_open(FILENAME,CFS_WRITE);

  for(i=0; i < 1; i++){
    memset(msg,0,payload);
    sprintf(msg, "data : %d\n",i);
    strncpy(cfs_buf,msg,sizeof(cfs_buf)-1);
    cfs_buf[sizeof(cfs_buf)-1] = '\0';
    int res = dtls_encrypt_data(ctx,session,msg,sizeof(msg),sendbuf,sizeof(sendbuf));
        printf("dtls_encrypt_data res:%d\n",res);
        if(fd >= 0){
          int res = cfs_write(fd,sendbuf,sizeof(sendbuf));
          printf("cfs_write_res: %d, sendbuf_size:%d\n",res,sizeof(sendbuf));
        } else{
          printf("\ncfs_file_open error!\n");
        }
  }
  cfs_close(fd);
  fd = cfs_open(FILENAME,CFS_READ);

}

static int
dtls_complete(struct dtls_context_t *ctx, session_t *session, int a, unsigned short msg_type){

  if(msg_type == DTLS_EVENT_CONNECTED){
    cfs_prepare_data(ctx,session);
	  connected = 1;
    char buf[30] = "start\n";
    dtls_write(ctx, session, (uint8 *)buf, sizeof(buf));

  } else if (msg_type == DTLS_EVENT_CONNECT){

  }

  return 0;
}

void
init_dtls(session_t *dst) {
  static dtls_handler_t cb = {
    .write = send_to_peer,
    .read  = read_from_peer,
    .event = dtls_complete,
#ifdef DTLS_PSK
    .get_psk_info = get_psk_info,
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
    .get_ecdsa_key = get_ecdsa_key,
    .verify_ecdsa_key = verify_ecdsa_key
#endif /* DTLS_ECC */
  };
  PRINTF("DTLS client started\n");

  print_local_addresses();

  dst->size = sizeof(dst->addr) + sizeof(dst->port);
  dst->port = UIP_HTONS(3000);

  //set_connection_address(&dst->addr);
  //client_conn = udp_new(&dst->addr, 0, NULL);
  client_conn = udp_new(&dst->addr, dst->port, NULL);
  udp_bind(client_conn, UIP_HTONS(3001));


  PRINTF("set connection address to ");
  PRINT6ADDR(&dst->addr);
  PRINTF(":%d\n", uip_ntohs(dst->port));

  dtls_set_log_level(DTLS_LOG_DEBUG);

  dtls_context = dtls_new_context(client_conn);
  if (dtls_context)
    dtls_set_handler(dtls_context, &cb);
}


/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  //static int connected = 0;
  static session_t dst;

  static struct etimer et;
  uip_ipaddr_t ipaddr;

  PROCESS_BEGIN();
  PRINTF("UDP client process started\n");


#if UIP_CONF_ROUTER
  printf("set global address test\n");
  set_global_address();
#endif

  dtls_init();

  static resolv_status_t status = RESOLV_STATUS_UNCACHED;
  while(status != RESOLV_STATUS_CACHED) {
    status = set_connection_address(&ipaddr);

    if(status == RESOLV_STATUS_RESOLVING) {
      PROCESS_WAIT_EVENT_UNTIL(ev == resolv_event_found);
    } else if(status != RESOLV_STATUS_CACHED) {
      PRINTF("Can't get connection address.\n");
      PROCESS_YIELD();
    }
  }

  /* new connection with remote host */
  dst.addr = ipaddr;
  init_dtls(&dst);
  serial_line_init();
  PRINTF("Created a connection with the server ");
  PRINT6ADDR(&client_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n",
	UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

  //etimer_set(&et, SEND_INTERVAL);

  dtls_connect(dtls_context, &dst);
  while(1) {
    PROCESS_YIELD();
    //if(etimer_expired(&et)) {
     // etimer_stop(&et);
      //dtls_connect(dtls_context, &dst);
      //etimer_restart(&et);
   // } else if(ev == tcpip_event) {
    if(ev == tcpip_event){

      printf("\nClient tcpip_event!!\n\n");
      dtls_handle_read(dtls_context);
    }
    /*if (connected){
      printf("\nconnected and send packet\n");
    }*/
    if (buflen) {
      if (!connected) {
	connected = dtls_connect(dtls_context, &dst) >= 0;
      }
      printf("connected: %d\n",connected);
      if(connected) try_send(dtls_context, &dst);
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
