/*  cert-parser.h
 *
 *
 *  This is a parser for X.509 ECC Certificates in PEM format that use
 *  ecdsa-sha keys.
 *
 *  It consists of two parts:
 *    I)  base64 decoding
 *    II) Parsing the decoded Certificate in its elements.
 *
 *  Created on: 16.01.2013
 *      Author: Hossein Shafagh <hossein.shafagh@rwth-aachen.de>
 *  Modified on: 24.04.2015
 *      Author: Tómas Þór Helgason <helgas@kth.se>
 */

#ifndef CERT_PARSER_H_
#define CERT_PARSER_H_

#include <stdint.h>

/* This struct holds pointers to different components of a Certificate in
 * process.
 *
 */
typedef struct dtls_certificate_context_t {
  unsigned char *TBSCertificate;
  uint16_t TBSCertificate_len;
  unsigned char *issuer;
  uint16_t issuer_len;
  unsigned char *subject;
  uint16_t subject_len;
  unsigned char *subject_pub_key;
  uint16_t subject_pub_key_len;
  unsigned char *signature;
} dtls_certificate_context_t;

uint16_t decode_b64(unsigned char *in, unsigned char *out, uint16_t len_in);
uint8_t cert_parse(unsigned char *certificate,
                   uint16_t certificate_len,
                   struct dtls_certificate_context_t *cert_ctx);
uint8_t cert_verfiy_signature(const struct dtls_certificate_context_t *cert_ctx,
                              const unsigned char *public_key_signer);

#endif /* CERT_PARSER_H_ */
