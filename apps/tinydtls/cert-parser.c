/*  cert-parser.c
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

#include <stdio.h>
#include <string.h>

#include "cert-parser.h"
#include "numeric.h"
#include "ecc/ecc.h"
#include "tinydtls-crypto.h"

/*---------------------------------------------------------------------------*/
/* RFC2459 ASN1
 * Only ECC relevant OID values
 * Can/should be extended stepwise to support wider range of certificates
 * and keys
 */
const unsigned char OID_ECPUBLICKEY[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const unsigned char OID_ECDSA_WITH_SHA1[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01 };
const unsigned char OID_ECDSA_WITH_SHA256[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
const unsigned char OID_PRIME256V1[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

/* Name types */
/*#define OID_ID_X520_AT                   {0x55, 0x04}
   #define OID_ID_AT_COMMONNAME             {0x55, 0x04, 0x03}
   #define OID_ID_AT_SURNAME                {0x55, 0x04, 0x04}
   #define OID_ID_AT_SERIALNUMBER           {0x55, 0x04, 0x05}
   #define OID_ID_AT_COUNTRYNAME            {0x55, 0x04, 0x06}
   #define OID_ID_AT_LOCALITYNAME           {0x55, 0x04, 0x07}
   #define OID_ID_AT_STATEORPROVINCENAME    {0x55, 0x04, 0x08}
   #define OID_ID_AT_STREETADDRESS          {0x55, 0x04, 0x09}
   #define OID_ID_AT_ORGANIZATIONNAME       {0x55, 0x04, 0x0A}
   #define OID_ID_AT_ORGANIZATIONALUNITNAME {0x55, 0x04, 0x0B}
   #define OID_ID_AT_TITLE                  {0x55, 0x04, 0x0C}
   #define OID_ID_AT_DESCRIPTION            {0x55, 0x04, 0x0D}
   #define OID_ID_AT_NAME                   {0x55, 0x04, 0x29}
   #define OID_ID_AT_GIVENNAME              {0x55, 0x04, 0x2A}
   #define OID_ID_AT_INITIALS               {0x55, 0x04, 0x2B}
   #define OID_ID_AT_GENERATIONQUALIFIER    {0x55, 0x04, 0x2C}
 #define OID_ID_AT_PSEUDONYM              {0x55, 0x04, 0x41} */

/* ASN1 different class tags*/
/* #define ASN1_BOOLEAN         0x01  // 1 */
#define ASN1_TAG_INTEGER     0x02  /* 2 */
#define ASN1_BIT_STRING      0x03  /* 3 */
/* #define ASN1_OCTET_STRING    0x04  // 4 */
/* #define ASN1_NULL            0x05  // 5 */
#define ASN1_OBJECT_ID       0x06  /* 6 */
/* #define ASN1_UTF8STRING      0x0C  // 12 */
/* #define ASN1_SEQUENCE        0x10  // 16 */
/* #define ASN1_SET             0x11  // 17 */
/* #define ASN1_PRINTABLESTRING 0x13  // 19 */
/* #define ASN1_T61STRING       0x14  // 20 */
/* #define ASN1_IA5STRING       0x16  // 22 */
/* #define ASN1_UTCTIME         0x17  // 23 */

/* Helpful ASN1 Macros */
#define ASN1_CONSTRUCTED_SEQ   0x30
#define ASN1_CONSTRUCTED_SET   0x31

#define B64_ENC_LENGTH   4
#define B64_DEC_LENGTH   3
#define P256_DIGIT_LEN   32

#define long_length(param) \
  (((param) & 0xf0) == 0x80) ? \
  ((param) & 0x0f) : 0x00

/*#define constructed_values(param) \
    (param && 0xdf) == 0x20 ?\
    1 : 0
 */
/*---------------------------------------------------------------------------*/
#define DEBUG 0
#if DEBUG
#include "lib/ecc/bigint.h"
#define PRINTF(...) printf(__VA_ARGS__)
#define HEXDUMP(...) hexdump(__VA_ARGS__)
#else
#define PRINTF(...)
#define HEXDUMP(...)
#endif
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
/*
 * Decode four '6-bit' base64 characters to three 8-bit characters
 */
static void
decode_b64_block(unsigned char *in, unsigned char *out)
{
  out[0] = (unsigned char)(in[0] << 2 | in[1] >> 4);
  out[1] = (unsigned char)(in[1] << 4 | in[2] >> 2);
  out[2] = (unsigned char)(((in[2] << 6) & 0xc0) | in[3]);
}
/*---------------------------------------------------------------------------*/
/*
 * Decode three '6-bit' base64 characters to two 8-bit characters
 */
static void
decode_b64_twobyte(unsigned char *in, unsigned char *out)
{
  out[0] = (unsigned char)(in[0] << 2 | in[1] >> 4);
  out[1] = (unsigned char)(in[1] << 4 | in[2] >> 2);
}
/*---------------------------------------------------------------------------*/
/*
 * Decode two '6-bit' base64 characters to one 8-bit characters
 */
static void
decode_b64_onebyte(unsigned char *in, unsigned char *out)
{
  out[0] = (unsigned char)(in[0] << 2 | in[1] >> 4);
}
/*
 * Decode base64 characters to 8-bit characters
 *
 * \param in     The input in base64 format (PEM)
 * \param out    The decoded input
 * \param len_in The length of input.
 *
 * \return       The length of decoded output
 */
uint16_t
decode_b64(unsigned char *in, unsigned char *out, uint16_t len_in)
{
/*
 * In the first step we have to convert ASCII to base64
 * Base64 uses only 6 bits (64 different characters).
 * However, the base64 characters have a different bit representation than
 * the same ASCII characters:
 *
 * CHAR     A..Z      a..z      0..9      +     /     =       -       NL
 * ASCII    65..90    97..122   48..57    43    47    61      45      10
 * base64   0..25     26..51    52  61    62    63    ignore  comment newline
 * DIF      -65       -71       -4
 *
 */

  /* It is possible to use the same buffer for input and output, but this is left
   * to the upper layer to use the same buffer for input and output.
   * Since the decoded output is about 3/4 shorter than the original,
   * this should not be any problem.
   *
   * Specially that the first 27 Bytes consist of BEGIN HEADER
   *
   * We put every 4 bytes into temporal buffer and decode
   * the result back to the buffer to avoid any problems with input without HEADER.
   */
  unsigned char b64_bucket[B64_ENC_LENGTH];
  memset(b64_bucket, 0, B64_ENC_LENGTH);
  uint8_t b64_index = 0;
  uint16_t len_out = 0;

  /* PEM consists of aligned lines with 64 characters (64 Byte),
   * except the last line.
   * After each line, a new line character 0x0a follows.
   */

  PRINTF("Convert ASCII to base64, len %u\n", len_in);
  uint16_t i;
  for(i = 0; i < len_in; i++) {
    /* TODO: (Figure out if the assumption is true!)
     * Another idea how to implement the conversion from ASCII value
     * to base64 values is to use an special array:
     * The index of the array element is the ASCII value and the content of
     * the element the base64 value. E.g. 'a' has the value
     * 97 in ASCII, and 26 in base64. This means:
     * conversion_array[97] = 27;
     * This requires less if-cases and is more efficient,
     * but might require more memory. (123 Byte for the array!)
     */
    if(b64_index == B64_ENC_LENGTH) {
      /* A four '6-bit' bucket: copy the last 4 */
      memcpy(b64_bucket, in + i - B64_ENC_LENGTH, B64_ENC_LENGTH);
      decode_b64_block(b64_bucket, out + len_out);
      b64_index = 0;
      len_out += B64_DEC_LENGTH;
    }
    if(in[i] == 45) {
      /* Comment line: BEGIN or END Header starting with -
       * Remove the header line: Discard all characters until the next line
       */
      while(in[i] != 10 && i < len_in) {
        i++;
      }
      PRINTF("Removed HEADER with length %u last char \n", i);
      HEXDUMP(in, i + 1);
      PRINTF("\n");
      continue;
    }
    if(in[i] >= 48 && in[i] <= 57) {
      /* 0..9 */
      in[i] += 4;
      b64_index++;
      continue;
    }
    if(in[i] >= 65 && in[i] <= 90) {
      /* A..Z */
      in[i] -= 65;
      b64_index++;
      continue;
    }
    if(in[i] >= 97 && in[i] <= 122) {
      /* a..z */
      in[i] -= 71;
      b64_index++;
      continue;
    }
    if(in[i] == 43) {
      /* + */
      in[i] = 62;
      b64_index++;
      continue;
    }
    if(in[i] == 47) {
      /* / */
      in[i] = 63;
      b64_index++;
      continue;
    }
    if(in[i] == 61) {
      /* = */
      in[i] = 0;
      /* The final line */
      if(i > 2) {
        memcpy(b64_bucket, in + i - 3, B64_ENC_LENGTH);
      }
      continue;
    }
    if(in[i] == 10) {
      /* new line */
      continue;
    }
    PRINTF("ERROR: unknown character %c \n", in[i]);
  }

  PRINTF("leftovers index %u \n", b64_index % B64_ENC_LENGTH);
  /* Handle Padding which can only occur at the end */
  switch(b64_index % B64_ENC_LENGTH) {
  case 0:
    /* Already decoded! */
    break;
  case 1:
    PRINTF("ERROR: wrong length\n");
    /* Probably done, remove the HEADER */
    break;
  case 2:
    decode_b64_onebyte(b64_bucket, out + len_out);
    len_out += 1;
    break;
  case 3:
    decode_b64_twobyte(b64_bucket, out + len_out);
    len_out += 2;
    break;
  default:
    PRINTF("ERROR: Modulo not working!\n");
    break;
  }

  PRINTF("Decoded length: %u \n", len_out);
  return len_out;
}
/*---------------------------------------------------------------------------*/
/* Parse the length field of the give ASN1 element.
 * The length field can be short or long.
 * The short length field is one byte.
 * The long length field has a variable length.
 *
 * \param certificate     pointer to the Certificate
 * \param unit_length     will hold the parsed element length after return
 * \param index           it holds the index of current element and points
 *                        the content of current element after return
 * \return                The type of the given element.
 */
static uint8_t
cert_get_element(const unsigned char *certificate,
                 uint16_t *unit_length,
                 uint16_t *index)
{
  uint8_t ret;
  /* move to the length field */
  (*index)++;

  /* return unit class, set unit_len and iterate index accordingly */
  ret = long_length(certificate[*index]);
  if(ret == 0) {
    /* One byte short length field */
    *unit_length = certificate[*index];
    (*index)++;
    PRINTF("segment-length-S1 len: %u, type: %02X\n", *unit_length, certificate[*index - 2]);
    return certificate[*index - 2];
  } else if(ret == 1) {
    /* One byte long length field */
    (*index)++;
    *unit_length = certificate[*index];
    (*index)++;
    PRINTF("segment-length-L1 len: %u, type: %02X\n", *unit_length, certificate[*index - 3]);
    return certificate[*index - ret - 2];
  } else if(ret == 2) {
    /* Two byte long length field */
    (*index)++;
    *unit_length = ((certificate[*index]) << 8);
    *unit_length |= certificate[*index + 1];
    (*index) += 2;
    PRINTF("segment-length-L2 len: %u, type: %02X\n", *unit_length, certificate[*index - 4]);
    return certificate[*index - ret - 2];
  } else {
    PRINTF("ERROR: Length format not supported!\n");
    return 0;
  }
}
static void
dtls_ec_key_to_uint32(const unsigned char *key, size_t key_size,
                      uint32_t *result)
{
  int i;

  for(i = (key_size / sizeof(uint32_t)) - 1; i >= 0; i--) {
    *result = dtls_uint32_to_int(&key[i * sizeof(uint32_t)]);
    result++;
  }
}
/*---------------------------------------------------------------------------*/
static uint8_t
cert_get_ecdsa_signature_param(const struct dtls_certificate_context_t *cert_ctx,
                               uint32_t *r, uint32_t *s)
{
  uint16_t i = 0;
  uint16_t element_len = 0;

  while(cert_ctx->signature[i] != ASN1_CONSTRUCTED_SEQ) {
    i++;
  }

  /* The first element contains the entire ECDSA Signature with r and s as INTEGER  */
  if(cert_get_element(cert_ctx->signature, &element_len, &i) != ASN1_CONSTRUCTED_SEQ) {
    /* Wrong formating: Certificate not starting with a constructed sequence */
    PRINTF("ERROR: Wrong Signature Sequence \n");
    return 0;
  }

  if(cert_get_element(cert_ctx->signature, &element_len, &i) != ASN1_TAG_INTEGER) {
    /* Wrong formating: Certificate not starting with a constructed sequence */
    PRINTF("ERROR: Wrong Signature Structure r \n");
    return 0;
  }
  /* TODO: FIX THIS CODE... could not always be what we want to remove 00 in */
  /*       front of the r value. */
  if(cert_ctx->signature[i] == 0x00) {
    i++;
    element_len--;
  }
  PRINTF("r %u \n", element_len);
  HEXDUMP(cert_ctx->signature + i, element_len);
  PRINTF("\n");
  dtls_ec_key_to_uint32(cert_ctx->signature + i, P256_DIGIT_LEN, r);
  i += element_len;

  if(cert_get_element(cert_ctx->signature, &element_len, &i) != ASN1_TAG_INTEGER) {
    /* Wrong formating: Certificate not starting with a constructed sequence */
    PRINTF("ERROR: Wrong Signature Structure s \n");
    return 0;
  }

  PRINTF("s %u \n", element_len);
  HEXDUMP(cert_ctx->signature + i, element_len);
  PRINTF("\n");
  dtls_ec_key_to_uint32(cert_ctx->signature + i, P256_DIGIT_LEN, s);

#if DEBUG
  PRINTF("Signature elements r and s from the Certificate:\n");
  bigint_print(r, 8);
  bigint_print(s, 8);
#endif /* DEBUG */
  return 1;
}
/*---------------------------------------------------------------------------*/
/* Given a Certificate and a public key, this function verifies
 * that the Certificate is signed with the given public key.
 * If this function returns 1, the public key can be used.
 *
 * \param cert_ctx           To be verified Certificate
 * \param public_key_signer  locally stored public key
 * \return                   1 if successful
 */
uint8_t
cert_verfiy_signature(const struct dtls_certificate_context_t *cert_ctx,
                      const unsigned char *public_key_signer)
{
  int result = 0;
  dtls_hash_ctx data;
  unsigned char sha256hash[DTLS_HMAC_DIGEST_SIZE];
  uint32_t point_r[8];
  uint32_t point_s[8];
  uint32_t hash[8];
  ecc_point_a pub;

  if(!cert_get_ecdsa_signature_param(cert_ctx, point_r, point_s)) {
    return 0;
  }
  dtls_hash_init(&data);
  dtls_hash_update(&data, cert_ctx->TBSCertificate, cert_ctx->TBSCertificate_len);
  dtls_hash_finalize(sha256hash, &data);

  dtls_ec_key_to_uint32(public_key_signer, P256_DIGIT_LEN, pub.x);
  dtls_ec_key_to_uint32(public_key_signer + P256_DIGIT_LEN, P256_DIGIT_LEN, pub.y);
  dtls_ec_key_to_uint32(sha256hash, DTLS_HMAC_DIGEST_SIZE, hash);

  result = ecc_check_signature_from_sha(&pub, hash, point_s, point_r);

  if(result < 0) {
    result = 1;
  }

#if DEBUG
  PRINTF("Signature %d: %s \n", result, (result) ? "Wrong" : "Correct");
  bigint_print(point_r, 8);
  bigint_print(point_s, 8);
#endif /* DEBUG */

  return result ? 0 : 1;
}
/*---------------------------------------------------------------------------*/
/*
 * Parse the give certificate into its element and store it in the given
 * struct.
 *
 * \param certificate       A pointer the buffer holding the to be parsed certificate
 * \param certificate_len   The length of decoded certificate (Can be used as a
 *                          hint to see if the certificate is a chain of certificates)
 * \param cert_ctx          A pointer to a struct holding pointers to parsed elements
 *                          of the to be verified certificate.
 * \return                  1 on success, 0 on failure
 */
uint8_t
cert_parse(unsigned char *certificate,
           uint16_t certificate_len,
           struct dtls_certificate_context_t *cert_ctx)
{

  uint16_t element_len = 0;
  uint16_t index = 0;

  /* The first element contains the entire Certificate  */
  if(cert_get_element(certificate, &element_len, &index) != ASN1_CONSTRUCTED_SEQ) {
    /* Wrong formating: Certificate not starting with a constructed sequence */
    PRINTF("ERROR: Wrong Certificate Sequence \n");
    return 0;
  }
  PRINTF("Encoded Certificate length %u ?= %u decoded length + 4 Header \n",
         certificate_len, element_len);

  /* The first element of the Certificate element is the data, which is the To Be Signed Certificate */
  cert_ctx->TBSCertificate = certificate + index;
  if(cert_get_element(certificate, &element_len, &index) != ASN1_CONSTRUCTED_SEQ) {
    /* Wrong formating: Certificate not having TBSCertificate */
    PRINTF("ERROR: Wrong Data Sequence \n");
    return 0;
  }
  PRINTF("Encoded TBSCertificate length %u \n",
         element_len);

  cert_ctx->TBSCertificate_len = element_len + 3; /* TBSCerticate HEADER 3 or 4 byte */

  PRINTF("TBSCertificate (without header)\n"); /* printing only the TBSCertificate without header*/
  HEXDUMP(cert_ctx->TBSCertificate + 3, cert_ctx->TBSCertificate_len - 3);
  PRINTF("\n");

  /* Set the index on the next element: Signing Algorithm  */
  index = cert_ctx->TBSCertificate_len + 4;  /* Certificate HEADER 4 */
  /* The second element of the Certificate element is the Sign-Algorithm*/
  if(cert_get_element(certificate, &element_len, &index) != ASN1_CONSTRUCTED_SEQ) {
    /* Wrong formating: Certificate not having Sign-Algorithm element */
    PRINTF("ERROR: Wrong Algo-ID Sequence \n");
    return 0;
  }
  PRINTF("Encoded Algo_ID length %u \n", element_len);

  /* Check if the provided signature algorithm is supported */
  if(memcmp(certificate + index + 2, OID_ECDSA_WITH_SHA256, element_len - 2) == 0) {
    PRINTF("ECDSA-WITH-SHA256\n");
  } else {
    PRINTF("ERROR: Signing Algo not supported!\n");
    return 0;
  }
  index += element_len;
  if(cert_get_element(certificate, &element_len, &index) != ASN1_BIT_STRING) {
    /* Wrong formating: Certificate not having Signature element */
    PRINTF("ERROR: Wrong Signature Segment \n");
    return 0;
  }
  /* The third element of the Certificate element is the Signature */
  cert_ctx->signature = certificate + index + 1;
  PRINTF("Signature index %u \n", index + 1);
  PRINTF("Signature %u\n", element_len - 1);
  HEXDUMP(cert_ctx->signature, element_len - 1);
  PRINTF("\n");

  /* Parsing different elements of the first element of the Certificate element */
  unsigned char *pointer = cert_ctx->TBSCertificate; /* TODO make this as define!t */
  index = 0;
  PRINTF("TBSCert\n");
  HEXDUMP(pointer, 4);
  PRINTF("\n");
  cert_get_element(pointer, &element_len, &index);
  /* Retrieve Issuer */
  while(cert_get_element(pointer, &element_len, &index) != ASN1_CONSTRUCTED_SEQ) {
    /* Continue until Sign-algo, which is the first Sequence after VERSION and Serial-No. */
    index += element_len;
  }
  index += element_len; /* going over OID_PUBLIC_KEY_ALGO */
  if(cert_get_element(pointer, &element_len, &index) != ASN1_CONSTRUCTED_SEQ) {
    PRINTF("ERROR: No Issuer!\n");
    return 0;
  }

  /* Issuere's set of attributes */
  /* FIXME: use the hash of issuer attribute to find the corresponding public key? */
  cert_ctx->issuer = pointer + index;
  cert_ctx->issuer_len = element_len;
  index += element_len;
  PRINTF("Issuer\n");
  HEXDUMP(cert_ctx->issuer, cert_ctx->issuer_len);
  PRINTF("\n");

  /* Retrieve Validity */
  if(cert_get_element(pointer, &element_len, &index) != ASN1_CONSTRUCTED_SEQ) {
    PRINTF("ERROR: No Validity!\n");
    return 0;
  }
  PRINTF("Validity\n");
  HEXDUMP(pointer + index, element_len);
  PRINTF("\n");

  /* TODO In case we have access to real world time, Check validity */
  index += element_len;

  /* Retrieve Subject */
  if(cert_get_element(pointer, &element_len, &index) != ASN1_CONSTRUCTED_SEQ) {
    return 0;
  }
  /* Subject's set of attributes */
  /* FIXME: use the hash of subject attribute to associate it with the public key? */
  cert_ctx->subject = pointer + index;
  cert_ctx->subject_len = element_len;
  index += element_len;
  PRINTF("Subject\n");
  HEXDUMP(cert_ctx->subject, cert_ctx->subject_len);
  PRINTF("\n");

  /* Retrieve Public key*/
  if(cert_get_element(pointer, &element_len, &index) != ASN1_CONSTRUCTED_SEQ) {
    PRINTF("ERROR: No Public Key!\n");
    return 0;
  }
  PRINTF("Pub key!\n");
  if(cert_get_element(pointer, &element_len, &index) != ASN1_CONSTRUCTED_SEQ) {
    PRINTF("ERROR: NO CURVE!\n");
    return 0;
  }
  PRINTF("CURVE!\n");
  if(cert_get_element(pointer, &element_len, &index) != ASN1_OBJECT_ID) {
    PRINTF("ERROR: NO KEY STRING!\n");
    return 0;
  }

  /* Check if a EC-Public-key is used:*/
  if(memcmp(pointer + index, OID_ECPUBLICKEY, element_len) == 0) {
    PRINTF("EC-Public-Key %u \n", element_len);
  } else {
    PRINTF("ERROR: Public key not supported!\n");
    return 0;
  }
  index += element_len;

  if(cert_get_element(pointer, &element_len, &index) != ASN1_OBJECT_ID) {
    PRINTF("ERROR: NO CURVE2!\n");
    return 0;
  }
  /* Check if the curve is supported: OID_PRIME256V1  */
  if(memcmp(pointer + index, OID_PRIME256V1, element_len) == 0) {
    PRINTF("Curve: Prime256V %u \n", element_len);
  } else {
    PRINTF("ERROR: Curve not supported!\n");
    return 0;
  }
  index += element_len;

  if(cert_get_element(pointer, &element_len, &index) != ASN1_BIT_STRING) {
    PRINTF("ERROR: NO Subject!\n");
    return 0;
  }
  /* OCTET STRING FLAG */
  cert_ctx->subject_pub_key = pointer + index + 2;
  cert_ctx->subject_pub_key_len = element_len - 2;

  PRINTF("Subject Public Key\n");
  HEXDUMP(cert_ctx->subject_pub_key, cert_ctx->subject_pub_key_len);
  PRINTF("\n");

  PRINTF("Parsing Successful \n");
  return 1;
}
/*---------------------------------------------------------------------------*/
/*
   Certificate: | 30 82 (270 + 4)
 |    Data: | 30 81 (181 + 3)
 |          |        Serial: | 02 09 (9 + 2)
 |          |       Sign-al: | 30 09 (9 + 2)
 |          |                |      OID  | 06 07 (7 + 2)
 |          |                |
 |          |        Issuer: | 30 0f (15 + 2)
 |          |                |      Set: | 31 0d (13 + 2)
 |          |                |           |    CN: | 30 0b (11 + 2)
 |          |                |           |        |  OID: | 06 03 (3 + 2)
 |          |                |           |        |  UTF8 | 0c 04 (4 + 2)
 |          |                |
 |          |      Validity: | 30 1e (30 + 2)
 |          |                |      UTC: | 17 0d (15 +2)
 |          |                |      UTC: | 17 0d (15 +2)
 |          |                |
 |          |       Subject: | 30 11 (17 + 2)
 |          |                |      Set: | 31 0f (15 + 2)
 |          |                |           |    CN: | 30 0d (13 +2)
 |          |                |           |        |  OID: | 06 03 (3 + 2)
 |          |                |           |        |  UTF8 | 0c 06 (6 + 2)
 |          |                |
 |          | Subject PB-key:| 30 59  (89 + 2)
 |          |                |     Algo: | 30 13 (19 + 2)
 |          |                |           |   OID: | 06 07 (7 + 2)
 |          |                |           |   OID: | 06 08 (8 + 2)
 |          |                |           |
 |          |                |    PB-key | 03 42 (66 + 2)
 |          |
 |          |
 | Sign-Algo| 30 09 (9 + 2)
 |          |           OID: | 06 07 (7 + 2)
 |          |
 |          |
 | Signature| 03 49 (73 + 2)
 |          |                |           |        |      |
   Tree-Depth:  0          1                2           3        4      5

   Certificates ::= SEQUENCE OF Certificate
   Certificate  ::=  SEQUENCE  {
     tbsCertificate       TBSCertificate,
     signatureAlgorithm   AlgorithmIdentifier,
     signatureValue       BIT STRING
   }
   TBSCertificate  ::=  SEQUENCE  {
     version         [0]  Version OPTIONAL, -- EXPLICIT nnn DEFAULT 1,
     serialNumber         CertificateSerialNumber,
     signature            AlgorithmIdentifier,
     issuer               Name,
     validity             Validity,
     subject              Name,
     subjectPublicKeyInfo SubjectPublicKeyInfo,
   }
   CertificateSerialNumber ::= INTEGER
   Version ::= INTEGER
   AlgorithmIdentifier ::= SEQUENCE {
   algorithm OBJECT IDENTIFIER,
   parameters  heim_any OPTIONAL
   }
   Validity ::= SEQUENCE {
     notBefore      Time,
     notAfter       Time
   }
   SubjectPublicKeyInfo  ::=  SEQUENCE  {
     algorithm            AlgorithmIdentifier,
     subjectPublicKey     BIT STRING
   }
   Name ::= SET OF AttributeTypeAndValue
   AttributeTypeAndValue ::= SEQUENCE {
        type    AttributeType,
        value   DirectoryString
   }
   SubjectPublicKeyInfo  ::=  SEQUENCE  {
     algorithm            AlgorithmIdentifier,
     subjectPublicKey     BIT STRING
   }

   Ecdsa-Sig-Value  ::=  SEQUENCE  {
     r     INTEGER,
     s     INTEGER
   }

 */