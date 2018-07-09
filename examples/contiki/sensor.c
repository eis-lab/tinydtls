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

#if UIP_CONF_IPV6_RPL
#include "net/rpl/rpl.h"
#endif

#include <string.h>
#include "tinydtls.h"

#ifndef DEBUG
#define DEBUG DEBUG_PRINT
#endif
#include "net/ip/uip-debug.h"

#include "debug.h"
#include "dtls.h"

#ifdef ENABLE_POWERTRACE
#include "powertrace.h"
#endif

#include "sys/rtimer.h"
#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

#define MAX_PAYLOAD_LEN 120
#define fusion fusion_DTLS

static int connected = 0;
static struct uip_udp_conn *server_conn;
static int rtimer_count = 0;
static int rtimer_count2 = 0;
static dtls_context_t *dtls_context;
int fd;
int receiver_num = 0;
#include "cfs-coffee.h"
#define FILENAME "test"
#define payload 30
char cfs_buf[payload];

static const unsigned char ecdsa_priv_key[] = {
                        0xD9, 0xE2, 0x70, 0x7A, 0x72, 0xDA, 0x6A, 0x05,
                        0x04, 0x99, 0x5C, 0x86, 0xED, 0xDB, 0xE3, 0xEF,
                        0xC7, 0xF1, 0xCD, 0x74, 0x83, 0x8F, 0x75, 0x70,
                        0xC8, 0x07, 0x2D, 0x0A, 0x76, 0x26, 0x1B, 0xD4};

static const unsigned char ecdsa_pub_key_x[] = {
                        0xD0, 0x55, 0xEE, 0x14, 0x08, 0x4D, 0x6E, 0x06,
                        0x15, 0x59, 0x9D, 0xB5, 0x83, 0x91, 0x3E, 0x4A,
                        0x3E, 0x45, 0x26, 0xA2, 0x70, 0x4D, 0x61, 0xF2,
                        0x7A, 0x4C, 0xCF, 0xBA, 0x97, 0x58, 0xEF, 0x9A};

static const unsigned char ecdsa_pub_key_y[] = {
                        0xB4, 0x18, 0xB6, 0x4A, 0xFE, 0x80, 0x30, 0xDA,
                        0x1D, 0xDC, 0xF4, 0xF4, 0x2E, 0x2F, 0x26, 0x31,
                        0xD0, 0x43, 0xB1, 0xFB, 0x03, 0xE2, 0x2F, 0x4D,
                        0x17, 0xDE, 0x43, 0xF9, 0xF9, 0xAD, 0xEE, 0x70};

PROCESS(udp_server_process, "UDP server process");
AUTOSTART_PROCESSES(&resolv_process,&udp_server_process);
/*---------------------------------------------------------------------------*/
static int
read_from_peer(struct dtls_context_t *ctx,
               session_t *session, uint8 *data, size_t len) {
  printf("\nread from peer func!\n");
  size_t i;
  for (i = 0; i < len; i++)
    PRINTF("%c", data[i]);

  char sendbuf[250];

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

  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);
  uip_ipaddr_copy(&conn->ripaddr, &session->addr);
  conn->rport = UIP_HTONS(3001);
  uip_udp_packet_send(conn, sendbuf, sizeof(sendbuf));

  /* Restore server connection to allow data from any node */
  /* FIXME: do we want this at all? */
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  rtimer_count2 = rtimer_arch_now() - rtimer_count;
  printf("dtls_send rtimer_count:%d\n",rtimer_count2);
  return 0;
}

static int
send_to_peer(struct dtls_context_t *ctx,
             session_t *session, uint8 *data, size_t len) {

  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);

  uip_ipaddr_copy(&conn->ripaddr, &session->addr);
  conn->rport = session->port;

  PRINTF("send to ");
  PRINT6ADDR(&conn->ripaddr);
  PRINTF(":%u\n", uip_ntohs(conn->rport));

  uip_udp_packet_send(conn, data, len);

  /* Restore server connection to allow data from any node */
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  return len;
}

#ifdef DTLS_PSK
/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
             dtls_credentials_type_t type,
             const unsigned char *id, size_t id_len,
             unsigned char *result, size_t result_length) {

  struct keymap_t {
    unsigned char *id;
    size_t id_length;
    unsigned char *key;
    size_t key_length;
  } psk[3] = {
    { (unsigned char *)"Client_identity", 15,
      (unsigned char *)"secretPSK", 9 },
    { (unsigned char *)"default identity", 16,
      (unsigned char *)"\x11\x22\x33", 3 },
    { (unsigned char *)"\0", 2,
      (unsigned char *)"", 1 }
  };

  if (type != DTLS_PSK_KEY) {
    return 0;
  }

  if (id) {
    int i;
    for (i = 0; i < sizeof(psk)/sizeof(struct keymap_t); i++) {
      if (id_len == psk[i].id_length && memcmp(id, psk[i].id, id_len) == 0) {
        if (result_length < psk[i].key_length) {
          dtls_warn("buffer too small for PSK");
          return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
        }

        memcpy(result, psk[i].key, psk[i].key_length);
        return psk[i].key_length;
      }
    }
  }
  return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}
#endif /* DTLS_PSK */

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
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Server IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
    }
  }
}

static void
dtls_handle_read(dtls_context_t *ctx) {
  session_t session;
  memset(&session, 0, sizeof(session_t));
  char *str; //test
  if(uip_newdata()) {
    str = uip_appdata; //test
    str[uip_datalen()] = '\0';
    uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
    session.port = UIP_UDP_BUF->srcport;
    session.size = sizeof(session.addr) + sizeof(session.port);

    PRINTF("sensor: received from ");
    PRINT6ADDR(&(session.addr));
    PRINTF(" :%d\n",uip_ntohs(session.port));

    dtls_handle_message(ctx, &session, uip_appdata, uip_datalen());
  }
}

void
cfs_prepare_data(struct dtls_context_t *ctx, session_t *session){

  char msg[payload];
  char sendbuf[250];
  int i;
  fd = cfs_open(FILENAME,CFS_WRITE);

  for(i=0; i < 1; i++){
    memset(msg,0,payload);
    sprintf(msg, "data : %d\n",i);
    strncpy(cfs_buf,msg,sizeof(cfs_buf)-1);
    cfs_buf[sizeof(cfs_buf)-1] = '\0';

    #ifdef fusion
    int res = dtls_encrypt_data(ctx,session,msg,sizeof(msg),sendbuf,sizeof(sendbuf));
    printf("dtls_encrypt_data res:%d\n",res);
    #endif

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
    receiver_num++;
    printf("dtls_connected!\n\n");
    if(receiver_num ==1){
    	 cfs_prepare_data(ctx,session);
	 connected = 1;
    }
  }
  return 0;
}

void
init_dtls() {
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

  PRINTF("DTLS server started\n");

  server_conn = udp_new(NULL, UIP_HTONS(3001), NULL);
  udp_bind(server_conn, UIP_HTONS(3000));

  dtls_set_log_level(DTLS_LOG_DEBUG);

  dtls_context = dtls_new_context(server_conn);
  if (dtls_context)
    dtls_set_handler(dtls_context, &cb);
}


/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{
  #if UIP_CONF_ROUTER
   uip_ipaddr_t ipaddr;
  #endif /* UIP_CONF_ROUTER */

  PROCESS_BEGIN();
  PRINTF("sensor started\n");

  #if RESOLV_CONF_SUPPORTS_MDNS
   resolv_set_hostname("sensor");
  #endif

  #if UIP_CONF_ROUTER
   uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
   uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
   uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
  #endif /* UIP_CONF_ROUTER */

  dtls_init();
  init_dtls();

  if(!dtls_context){
    dtls_emerg("cannot create context\n");
    PROCESS_EXIT();
  }

  print_local_addresses();

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {

      dtls_handle_read(dtls_context);
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
