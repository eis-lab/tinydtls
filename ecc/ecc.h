#ifndef _ECC_H__
#define _ECC_H__

#include "bigint.h"

typedef struct curve {
  u_word a[NUMWORDS];
  u_word b[NUMWORDS];
} ecc_curve;

typedef struct point_affine {
  u_word x[NUMWORDS];
  u_word y[NUMWORDS];
} ecc_point_a;

typedef struct point_projective {
  u_word x[NUMWORDS];
  u_word y[NUMWORDS];
  u_word z[NUMWORDS];
} ecc_point_p;

typedef struct elliptic_param {
  u_word p[NUMWORDS];

  ecc_curve curve;

  ecc_point_a point;

  u_word order[NUMWORDS + 1];

} ecc_param;

void new_ecc_init();

void ecc_affine_add(ecc_point_a * a, ecc_point_a * b, ecc_point_a * c,
                    u_word * p, u_word * a_c);

void ecc_aff_scalar_multiplication(ecc_point_a * R, ecc_point_a * a,
                                   u_word * k, u_byte digitsk, u_word * P,
                                   u_word * a_c);

void ecc_homogeneous_add(ecc_point_p * a, ecc_point_p * b, ecc_point_p * c,
                         u_word * p, u_word * a_c);

void ecc_scalar_multiplication_homo(ecc_point_a * R, ecc_point_a * a,
                                          u_word * k, u_byte digitsk,
                                          u_word * P, u_word * a_c);

void ecc_jacobian_add(ecc_point_p * a, ecc_point_p * b, ecc_point_p * c,
                 u_word * p, u_word * a_c);

void ecc_scalar_multiplication_jacob(ecc_point_a * R, ecc_point_a * a, 
                                    u_word * k, u_byte digitsk, u_word * p, 
                                    u_word * a_c);

void ecc_scalar_multiplication_ltr_jacob(ecc_point_a * R, ecc_point_a * a,
                                    u_word * k, u_byte digitsk, u_word * p,
                                    u_word * a_c);

void ecc_jacobian_double(ecc_point_p * a, ecc_point_p * b, u_word * p,
                         u_word * a_c);

#ifdef HW_ECC
void ecc_aff_hw_add(ecc_point_a * a, ecc_point_a * b, ecc_point_a * c,
                    u_word * p, u_word * a_c);


void ecc_scalar_multiplication_hw(ecc_point_a * R, ecc_point_a * a, 
                                    u_word * k, u_byte digitsk, u_word * p, 
                                    u_word * a_c);
#endif /* HW_ECC */

void ecc_generate_private_key(u_word * secr);

void ecc_generate_public_key(u_word * secr, ecc_point_a * publ);

#ifdef COMPACT_COORDINATES
uint8_t ecc_generate_shared_key(u_word * shar, u_word * secr, u_word * publx);
#else
uint8_t ecc_generate_shared_key(u_word * shared, u_word * secr,
                             ecc_point_a * publ);
#endif /* COMPACT_COORDINATES */

uint32_t ecc_generate_shared_key_and_iv(uint8_t * shared, uint8_t * iv, 
                                    u_word * secr, ecc_point_a * publ);

void ecc_generate_signature_from_sha(u_word * secr, u_word * e,
                                     u_word * signature, u_word * rx);

uint8_t ecc_check_signature_from_sha(ecc_point_a * public, u_word * e,
                                     u_word * signature, u_word * r);

uint32_t ecc_check_point(ecc_point_a * point);

void bigint_generate_full_point_from_x(ecc_point_a * point);

#endif
