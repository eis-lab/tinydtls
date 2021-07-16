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
#include "dev/rom-util.h"
#include "dev/ctr.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include "sys/etimer.h"
#include "dev/leds.h"
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

#include <string.h>
#include "debug.h"

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define MAX_PAYLOAD_LEN 120

static struct uip_udp_conn *server_conn;
static rtimer_clock_t rtimer_count, rtimer_count2;
static int virtual_peer_created = 0;
static int handshake_completed = 0;
static int receiver_num = 0;
static int packet_num = 50;
static int send_count = 0;

#define CTR 1
#include "dtls.h"
#include "tiny-AES-c/aes.h"
//#include "aes.h"
#include "sys/etimer.h"
#include "cfs-coffee.h"

#define FDTLS
//#define HW_AES
//#define ENERGY_TEST
#define FILENAME "cfs_file_name"
#define PAYLOAD 32
#define BUF_SIZE sizeof(dtls_record_header_t)+ 8 + 8 + PAYLOAD //
#define INTERVAL 30
/// payload 60- interval 47
int fd;
char cfs_buf[PAYLOAD];
static dtls_context_t *dtls_context;
session_t *vir_sess;


#ifndef FDTLS

#define NONCE_MAX_LEN   0
#define ICTR_MAX_LEN    16
#define MDATA_MAX_LEN   64

static const uint8_t keys128[][16] = {
  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
  };

static const struct {
  const void *keys;
  uint8_t key_size;
  uint8_t count;
} keys = { keys128, AES_KEY_STORE_SIZE_KEY_SIZE_128,sizeof(keys128) / sizeof(keys128[0])};

static const struct {
  bool encrypt;
  uint8_t key_size_index;
  uint8_t key_area;
  uint8_t nonce[NONCE_MAX_LEN];
  uint8_t ictr[ICTR_MAX_LEN];
  uint8_t ctr_len;
  uint8_t mdata[MDATA_MAX_LEN];
  uint16_t mdata_len;
  uint8_t expected[MDATA_MAX_LEN];
} ctr_vectors =
  {
    true,
    0,
    0,
    {},
    { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
      0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff },
    16,
    { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
      0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
      0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
      0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
      0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 },
    64,
    { 0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
      0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
      0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
      0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
      0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e,
      0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
      0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1,
      0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee }
  };

static rtimer_clock_t time1, time2, total_time;
#endif


PROCESS(udp_server_process, "UDP server process");
AUTOSTART_PROCESSES(&resolv_process,&udp_server_process);

/*---------------------------------------------------------------------------*/
static int
read_from_peer(struct dtls_context_t *ctx,
               session_t *session, uint8 *data, size_t len) {

  int epoch = 0;		        /**< counter for cipher state changes */
  int seq = 0;
  rtimer_clock_t tt2;
  rtimer_clock_t tt3,tt4,tt5 =0;
  rtimer_count = rtimer_arch_now();
  cfs_prepare_data(dtls_context,vir_sess);
  tt2 = rtimer_arch_now() - rtimer_count;

  fd = cfs_open(FILENAME,CFS_READ);

#ifdef FDTLS
  char* sendbuf = (char*)malloc(sizeof(uint8_t)*BUF_SIZE);
  int k;
  struct uip_udp_conn *conn;

#ifdef ENERGY_TEST
  for(k=0; k<INTERVAL; k++){
#endif //ENERGY_TEST
    tt3 = rtimer_arch_now();
    int r = cfs_read(fd, sendbuf+21, BUF_SIZE-21);
    tt4 = rtimer_arch_now() - tt3;
    tt5 += tt4;
    if(r == 0) {
      printf("r is 0\n");
      cfs_close(fd);
      return 0;
    } else if(r < BUF_SIZE-21) {
      printf("close cfs\n");
      cfs_close(fd);
      return 0;
    }

    fdtls_set_record_header(sendbuf,PAYLOAD,epoch,seq);

#ifdef ENERGY_TEST
    if(k%packet_num == 0 ){
      cfs_seek(fd, 0, CFS_SEEK_SET);
    }
#endif //ENERGY_TEST

    conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);
    uip_ipaddr_copy(&conn->ripaddr, &session->addr);
    conn->rport = UIP_HTONS(3001);

#ifdef ENERGY_TEST
  }
#endif //ENERGY_TEST

#ifdef ENERGY_TEST
  rtimer_count2 = rtimer_arch_now() - rtimer_count;
  printf("FDTLS encrypt + cfs_write(PAYLOAD: %d, write:%d, INTERVAL:%d):%d\n",PAYLOAD,BUF_SIZE-21,INTERVAL,tt2);
  printf("FDTLS total (PAYLOAD:%d, INTERVAL:%d): %d\n",PAYLOAD,INTERVAL,rtimer_count2);
  printf("fdtls_set_header:%d\n",tt5);
  //printf("FDTLS prepare data:%d\n",tt2);
#endif //ENERGY TEST

  //uip_udp_packet_send(conn, sendbuf, sizeof(sendbuf));

  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

#ifndef ENERGY_TEST
  rtimer_count2 = rtimer_arch_now() - rtimer_count;
  printf("FDTLS total (PAYLOAD:%d): %d\n",PAYLOAD,rtimer_count2);
  printf("FDTLS prepare data:%d\n",tt2);
  //send_count++;
#endif //SPEED TEST

#else //DTLS!!

  char buf[PAYLOAD];
  char mdata[PAYLOAD];
  uint8_t ret;
  int8_t res;
  int k;

#ifdef ENERGY_TEST
  for(k=0; k<INTERVAL; k++){
#endif
    int r = cfs_read(fd,&buf,PAYLOAD);
    if(r == 0 ){
      printf("r is 0\n");
      cfs_close(fd);
      return 0;
    } else if(r < sizeof(buf)){
      printf("close cfs\n");
      cfs_close(fd);
      return 0;
    }

#ifdef ENERGY_TEST
    /*if(k%packet_num == 0 ){
      cfs_seek(fd, 0, CFS_SEEK_SET);
    }*/
#endif
  //  #ifdef HW_AES
        /*crypto_enable();

        ret = aes_load_keys(keys.keys,keys.key_size, keys.count, 0);
        if(ret != 0){
          dtls_debug("aes_load_keys error iteration");
          return 0;
        }

        rom_util_memcpy(mdata, buf, PAYLOAD);
        ret = ctr_crypt_start(true, ctr_vectors.key_area,
                                ctr_vectors.nonce, ctr_vectors.ictr, ctr_vectors.ctr_len,
                                mdata, mdata, PAYLOAD,
                                &udp_server_process);
        if(ret !=0 ){
          dtls_debug("aes_load_keys error iteration");
          return 0;
        }

        while((res = ctr_crypt_check_status()) == CRYPTO_PENDING);

       crypto_disable();

       dtls_write(ctx,session,(uint8 *)mdata,PAYLOAD);*/
  // #else  //SW_AES
       struct AES_ctx aes_ctx;
       AES_init_ctx_iv(&aes_ctx, keys.keys,ctr_vectors.ictr);
       AES_CTR_xcrypt_buffer(&aes_ctx, buf, PAYLOAD);
       printf("buf:%s\n",buf);

  // #endif //HW_AES

#ifdef ENERGY_TEST
    }
#endif

  rtimer_count2 = rtimer_arch_now() - rtimer_count;
  printf("DTLS encrypt + cfs_write(PAYLOAD: %d, INTERVAL:%d):%d\n",PAYLOAD,INTERVAL,tt2);
  printf("DTLS total (PAYLOAD:%d, INTERVAL:%d): %d\n",PAYLOAD,INTERVAL,rtimer_count2);
#endif //FDTLS

  return 0;
}

static int
send_to_peer(struct dtls_context_t *ctx,
             session_t *session, uint8 *data, size_t len) {

  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);

  uip_ipaddr_copy(&conn->ripaddr, &session->addr);
  conn->rport = session->port;

  //PRINTF("send to ");
  //PRINT6ADDR(&conn->ripaddr);
  //PRINTF(":%u\n", uip_ntohs(conn->rport));
  /*if(handshake_completed == 1 ){
    rtimer_count2 = rtimer_arch_now() - rtimer_count;
    printf("DTLS basic count: %d\n", rtimer_count2);
    //printf("DTLS basic: %d ms\n",(uint32_t)((uint64_t)rtimer_count2 *1000/ RTIMER_SECOND));
  }*/

  if(handshake_completed == 0){
    uip_udp_packet_send(conn, data, len);
  }
  /*if(handshake_completed == 1 ){
    rtimer_count2 = rtimer_arch_now() - rtimer_count;
    printf("DTLS basic count: %d\n", rtimer_count2);
    //printf("DTLS basic: %d ms\n",(uint32_t)((uint64_t)rtimer_count2 *1000/ RTIMER_SECOND));
  }*/
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

    //PRINTF("server: received from ");
    //PRINT6ADDR(&(session.addr));
    //PRINTF(" :%d\n",uip_ntohs(session.port));

    dtls_handle_message(ctx, &session, uip_appdata, uip_datalen());
  }
}

cfs_prepare_data(struct dtls_context_t *ctx, session_t *session){

  char msg[PAYLOAD] = "data";
  char sendbuf[BUF_SIZE];
  char mdata[PAYLOAD];
  int i;

  cfs_coffee_reserve(FILENAME,4096);
  fd = cfs_open(FILENAME,CFS_WRITE);


#ifndef FDTLS
   uint8_t ret;
   int8_t res;
   crypto_init();
#endif

  for(i=0; i < INTERVAL; i++){
#ifdef FDTLS
      dtls_encrypt_data(ctx,session,msg,sizeof(msg),sendbuf,sizeof(sendbuf));
#else
    /*  #ifdef HW_AES
        crypto_enable();
        ret = aes_load_keys(keys.keys,keys.key_size, keys.count, 0);
        if(ret != 0){
          printf("aes_load_keys error iteration\n");
        }
        rom_util_memcpy(mdata, ctr_vectors.mdata, PAYLOAD);


        ret = ctr_crypt_start(false, ctr_vectors.key_area,
                                ctr_vectors.nonce, ctr_vectors.ictr, ctr_vectors.ctr_len,
                                mdata, mdata, PAYLOAD,
                                &udp_server_process);

        while((res = ctr_crypt_check_status()) == CRYPTO_PENDING);

        crypto_disable();
      #else*/
        //Use Tiny-AES library
        char aes_buf[PAYLOAD] = "data";
        struct AES_ctx aes_ctx;
        AES_init_ctx_iv(&aes_ctx, keys.keys,ctr_vectors.ictr);
        AES_CTR_xcrypt_buffer(&aes_ctx, aes_buf, PAYLOAD);

      //#endif

#endif
    if(fd >= 0){
        #ifdef FDTLS
          int res = cfs_write(fd,sendbuf+21,BUF_SIZE-21);
        #else
          int res = cfs_write(fd,mdata,PAYLOAD);
        #endif

        if(res < 0){
          printf("maximum size: BUF_SIZE*i = %d\n",BUF_SIZE*i);
          printf("iteration: %d\n", i);
          return -1;
        }
    }
  }
  cfs_close(fd);
}

static int
dtls_complete(struct dtls_context_t *ctx, session_t *session, int a, unsigned short msg_type){

  if(msg_type == DTLS_EVENT_CONNECTED){
       virtual_peer_created = 1;
       if(virtual_peer_created) {
         handshake_completed = 1;
         receiver_num++;
       }

       if(receiver_num == 1){

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
  //dtls_set_log_level(DTLS_LOG_DEBUG);
  server_conn = udp_new(NULL, UIP_HTONS(3001), NULL);
  udp_bind(server_conn, UIP_HTONS(3000));

  dtls_context = dtls_new_context(server_conn);
  if (dtls_context)
    dtls_set_handler(dtls_context, &cb);
}

void
led_function(){

  leds_on(LEDS_ALL);
  printf("leds_off\n");
}

#define NONCE_MAX_LEN   0
#define ICTR_MAX_LEN    16
#define MDATA_MAX_LEN   64
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{

 leds_on(LEDS_ALL);


#if UIP_CONF_ROUTER
  uip_ipaddr_t ipaddr;
#endif /* UIP_CONF_ROUTER */

PROCESS_BEGIN();

#if RESOLV_CONF_SUPPORTS_MDNS
  resolv_set_hostname("contiki-udp-server");
#endif

#if UIP_CONF_ROUTER
  uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
#endif /* UIP_CONF_ROUTER */

  print_local_addresses();

  dtls_init();
  init_dtls();

   //create virtual peer
   //rtimer_count = rtimer_arch_now();
   unsigned char id[] = "Client_identity";
   vir_sess = (session_t*)malloc(sizeof(session_t));
   if(create_virtual_peer(dtls_context,vir_sess,"Client_identity",15) != 0){
     printf("create virtual peer error\n");
   }
   //calculate keyblock using virtual peer and "psk id"
   calculate_key_block_self(dtls_context,vir_sess);
   //rtimer_count2 = rtimer_arch_now() - rtimer_count;

   //printf("virtual_peer count: %d\n", rtimer_count2);
   //printf("virtual_peer: %d ms\n",(uint32_t)((uint64_t)rtimer_count2 *1000/ RTIMER_SECOND));
   //prepare data using key block

   //cfs_prepare_data(dtls_context,vir_sess);

  static struct stimer et;
  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      if(handshake_completed){
        //clock_delay(10000); //10ms delay
        rtimer_count = rtimer_arch_now();
      }

      dtls_handle_read(dtls_context);

    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
