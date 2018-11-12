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

#include "tinydtls.h"
#include "dtls.h"
#include "debug.h"
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ip/resolv.h"

#include <string.h>
#include <stdbool.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

static struct uip_udp_conn *client_conn;
static int total_count = 0;
static int rtimer_count = 0;
static int rtimer_count2 = 0;
static int receive_num = 0;
#include "sys/rtimer.h"
#include "dev/leds.h"
/*-------------------------FIX-------------------------------------*/
#ifdef DTLS_PSK
#define PSK_ID_MAXLEN 32
#define PSK_MAXLEN 32
#define PSK_DEFAULT_IDENTITY "Client_identity"
#define PSK_DEFAULT_KEY      "secretPSK"
#endif /* DTLS_PSK */

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

#define SEND_INTERVAL		10 * CLOCK_SECOND
#define MAX_PAYLOAD_LEN		120

static dtls_context_t *dtls_context;
static char buf[] = "data reqeust\n";
static size_t buflen = 0;
static int handshake_complete = 0;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&resolv_process,&udp_client_process);
/*---------------------------------------------------------------------------*/

static void
try_send(struct dtls_context_t *ctx, session_t *dst) {

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

  receive_num++;
  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);
  uip_ipaddr_copy(&conn->ripaddr, &session->addr);
  conn->rport = UIP_HTONS(3000);

  /* Restore server connection to allow data from any node */
  /* FIXME: do we want this at all? */
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  rtimer_count2 = rtimer_arch_now() - rtimer_count;
  if(receive_num < 100) {
    total_count += rtimer_count2;
    //printf("count:%d\n",rtimer_count2);
    //get_rssi();
    dtls_write(ctx, session, (uint8 *)buf, buflen);
    rtimer_count = rtimer_arch_now();
  } else{
    printf("\nend total count:%d\n",total_count);
    //printf("seconds:%15.10f\n",total_count/RTIMER_ARCH_SECOND);
  }
  return 0;
}

static int
send_to_peer(struct dtls_context_t *ctx,
             session_t *session, uint8 *data, size_t len) {

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


static void
dtls_handle_read(dtls_context_t *ctx) {
  session_t session;
  memset(&session, 0, sizeof(session_t));

  if(uip_newdata()) {
    uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
    session.port = UIP_UDP_BUF->srcport;
    session.size = sizeof(session.addr) + sizeof(session.port);

    ((char *)uip_appdata)[uip_datalen()] = 0;
    //PRINTF("\nreceiver received message from: ");
    //PRINT6ADDR(&session.addr);
    //PRINTF(":%d\n", uip_ntohs(session.port));

    dtls_handle_message(ctx, &session, uip_appdata, uip_datalen());
  }
}

static int
dtls_complete(struct dtls_context_t *ctx, session_t *session, int a, unsigned short msg_type){

  if(msg_type == DTLS_EVENT_CONNECTED) {
    handshake_complete = 1;
    buflen = sizeof(buf);
    dtls_write(ctx, session, (uint8 *)buf, buflen);
    rtimer_count = rtimer_arch_now();
  }

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

  dst->size = sizeof(dst->addr) + sizeof(dst->port);
  dst->port = UIP_HTONS(3000);


  client_conn = udp_new(&dst->addr, dst->port, NULL);
  udp_bind(client_conn, UIP_HTONS(3001));


  PRINTF("set connection address to ");
  PRINT6ADDR(&dst->addr);
  PRINTF(":%d\n", uip_ntohs(dst->port));

  //dtls_set_log_level(DTLS_LOG_DEBUG);

  dtls_context = dtls_new_context(client_conn);
  if (dtls_context)
    dtls_set_handler(dtls_context, &cb);
}

/*-----------------------------------------------------------------------------------------*/

static void
tcpip_handler(void)
{
  char *str;

  if(uip_newdata()) {
    str = uip_appdata;
    str[uip_datalen()] = '\0';
    printf("Response from the server: '%s'\n", str);
  }
}

static void
timeout_handler(void)
{
  static int seq_id;

  printf("Client sending to: ");
  PRINT6ADDR(&client_conn->ripaddr);


#if SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION
  uip_udp_packet_send(client_conn, buf, UIP_APPDATA_SIZE);
#else /* SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION */
  uip_udp_packet_send(client_conn, buf, strlen(buf));
#endif /* SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION */
}

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

#if UIP_CONF_ROUTER
static void
set_global_address(void)
{
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
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
#define UDP_CONNECTION_ADDR       fd00:0:0:0:0212:7404:0004:0404
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

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static session_t dst;
  static struct etimer et;

  uip_ipaddr_t ipaddr;
  int connected = 0;

  PROCESS_BEGIN();

#if UIP_CONF_ROUTER
  set_global_address();
#endif

  print_local_addresses();

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

  dtls_init();

  dst.addr = ipaddr;
  init_dtls(&dst);
  dtls_connect(dtls_context, &dst);

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event){
        dtls_handle_read(dtls_context);
    }
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
