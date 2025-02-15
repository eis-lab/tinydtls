#include "ecc.h"
#include "random.h"
#include <string.h>
#include <stdio.h>              /* For printf() */

#undef DEBUG
#define DEBUG 0

#if DEBUG
#define DBG_PRINT(...) printf(__VA_ARGS__)
#else
#define DBG_PRINT(...)
#endif

#ifdef HW_ECC
#include "cpu/cc2538/dev/pka.h"
#include "cpu/cc2538/dev/ecc-curve-info.h"
static tECCCurveInfo hw_curve_param; 
#endif

static ecc_param param;

void
new_ecc_init()
{ 
  printf("Initializing ECC library\n");
#ifdef AFFINE_COORDINATES
  DBG_PRINT("AFFINE COORDINATES ");
#elif HOMOGENEOUS_COORDINATES
  DBG_PRINT("HOMOGENEOUS COORDINATES ");  
#elif JACOBIAN_COORDINATES
  DBG_PRINT("JACOBIAN COORDINATES ");
#endif 
  DBG_PRINT("Key Length %u, Word size %u\n",KEY_LENGTH_BITS, BIGINT_WORD_BITS);
  
  get_curve_parameters(&param);  
  
#ifdef HW_ECC
  DBG_PRINT("Using HW ECC\n");
  pka_init();
  pka_enable();
  hw_curve_param.name = "HW curve";
  hw_curve_param.ui8Size = NUMWORDS;
  hw_curve_param.pui32Prime = param.p;
  hw_curve_param.pui32N = param.order;
  hw_curve_param.pui32A = param.curve.a;
  hw_curve_param.pui32B = param.curve.b;
  hw_curve_param.pui32Gx = param.point.x;
  hw_curve_param.pui32Gy = param.point.y;
#endif
}


void
bigint_generate_full_point_from_x(ecc_point_a * point) {
  u_word aux[NUMWORDS], aux2[NUMWORDS];

  power_mod(aux, point->x, 3, NUMWORDS, param.p, NUMWORDS);
  bigint_mod_multiply(aux2, point->x, param.curve.a, param.p, NUMWORDS,
                      NUMWORDS);
  bigint_mod_add(aux, aux, aux2, param.p, NUMWORDS);
  bigint_mod_add(aux, aux, param.curve.b, param.p, NUMWORDS);

  bigint_mod_square_root(aux, aux, param.p, NUMWORDS);

  bigint_copy(aux, point->y, NUMWORDS);
}     

void
ecc_affine_add(ecc_point_a * a, ecc_point_a * b, ecc_point_a * c, u_word * p,
               u_word * a_c)
{                               //A=B+C
  
  u_word x[NUMWORDS], y[NUMWORDS], lambda[NUMWORDS * 2];

  u_word aux1[NUMWORDS];
  u_word aux2[NUMWORDS];

  bigint_null(x, NUMWORDS);
  bigint_null(y, NUMWORDS);
  bigint_null(lambda, 2 * NUMWORDS);
  bigint_null(aux1, NUMWORDS);
  bigint_null(aux2, NUMWORDS);

  if(!bigint_digit_length(b->x, NUMWORDS)) {
    if(!bigint_digit_length(b->y, NUMWORDS)) {  //If b point at infinity A = C 
      bigint_copy(c->x, a->x, NUMWORDS);
      bigint_copy(c->y, a->y, NUMWORDS);
      return;

    }
  }

  if(!bigint_digit_length(c->x, NUMWORDS)) {
    if(!bigint_digit_length(c->y, NUMWORDS)) {  //If c == (@,@) A = B 
      bigint_copy(b->x, a->x, NUMWORDS);
      bigint_copy(b->y, a->y, NUMWORDS);
      return;
    }
  }

  if(!bigint_compare(b->x, c->x, NUMWORDS)) {
    if(bigint_compare(b->y, c->y, NUMWORDS)) {  //X1 == X2 Y1 != Y2 A = (@,@)
      bigint_null(a->x, NUMWORDS);
      bigint_null(a->y, NUMWORDS);
      return;
    } else {                    //X1 == X2, Y1 == Y2
      if(bigint_is_zero(b->y, NUMWORDS)) {      // Y1 == Y2 == 0 A =(@,@)
        bigint_null(a->x, NUMWORDS);
        bigint_null(a->y, NUMWORDS);
        return;
      } else {                  //B==C, double point
        aux1[0] = 3;
        power_mod(aux2, b->x, 2, NUMWORDS, p, NUMWORDS);
        bigint_mod_multiply(aux1, aux2, aux1, p, NUMWORDS, 1);
        bigint_mod_add(aux1, aux1, a_c, p, NUMWORDS);
        bigint_null(aux2, NUMWORDS);

        aux2[0] = 2;
        bigint_mod_multiply(aux2, b->y, aux2, p, NUMWORDS, 1);
        bigint_modular_inverse(aux2, aux2, p, NUMWORDS);

        bigint_mod_multiply(lambda, aux1, aux2, p, NUMWORDS, NUMWORDS);
        bigint_null(aux2, NUMWORDS);
        aux2[0] = 2;
        bigint_mod_multiply(aux2, b->x, aux2, p, NUMWORDS, 1);
        power_mod(aux1, lambda, 2, NUMWORDS, p, NUMWORDS);

        bigint_mod_substract(x, aux1, aux2, p, NUMWORDS);
        bigint_mod_substract(aux1, b->x, x, p, NUMWORDS);
        bigint_mod_multiply(aux2, aux1, lambda, p, NUMWORDS, NUMWORDS);
        bigint_mod_substract(a->y, aux2, b->y, p, NUMWORDS);
        bigint_copy(x, a->x, NUMWORDS);
      }
    }
  } else {                      // X1 != X2
    bigint_mod_substract(aux1, c->y, b->y, p, NUMWORDS);
    bigint_mod_substract(aux2, c->x, b->x, p, NUMWORDS);
    bigint_modular_inverse(aux2, aux2, p, NUMWORDS);
    bigint_mod_multiply(lambda, aux1, aux2, p, NUMWORDS, NUMWORDS);
    bigint_mod_add(aux1, b->x, c->x, p, NUMWORDS);
    power_mod(aux2, lambda, 2, NUMWORDS, p, NUMWORDS);
    bigint_mod_substract(x, aux2, aux1, p, NUMWORDS);
    bigint_mod_substract(aux1, b->x, x, p, NUMWORDS);
    bigint_mod_multiply(aux2, aux1, lambda, p, NUMWORDS, NUMWORDS);
    bigint_mod_substract(a->y, aux2, b->y, p, NUMWORDS);
    bigint_copy(x, a->x, NUMWORDS);
  }

}

void
ecc_aff_scalar_multiplication(ecc_point_a * R, ecc_point_a * a, u_word * k,
                              u_byte digitsk, u_word * p, u_word * a_c)
{

  u_byte i, j;

  ecc_point_a N, res;

  bigint_copy(a->x, N.x, NUMWORDS);
  bigint_copy(a->y, N.y, NUMWORDS);

  bigint_null(res.x, NUMWORDS);
  bigint_null(res.y, NUMWORDS);

  for(i = 0; i < (digitsk - 1); i++) {
    for(j = 0; j < BIGINT_WORD_BITS; j++) {
      if((k[i] >> j) & 1) {
        ecc_affine_add(&res, &res, &N, p, a_c);
      }
      ecc_affine_add(&N, &N, &N, p, a_c);
    }
  }

  i = digitsk - 1;
  for(j = 0; j < bigint_bit_length(&k[i], 1); j++) {
    if((k[i] >> j) & 1) {
      ecc_affine_add(&res, &res, &N, p, a_c);
    }
    ecc_affine_add(&N, &N, &N, p, a_c);
  }

  bigint_copy(res.x, R->x, NUMWORDS);
  bigint_copy(res.y, R->y, NUMWORDS);
}

void
ecc_homogeneous_add(ecc_point_p * a, ecc_point_p * b, ecc_point_p * c,
                    u_word * p, u_word * a_c)
{

  u_word u[NUMWORDS], v[NUMWORDS];
  u_word aux1[NUMWORDS], aux2[NUMWORDS];
  u_word x3[NUMWORDS], y3[NUMWORDS], z3[NUMWORDS];

  bigint_null(u, NUMWORDS);
  bigint_null(v, NUMWORDS);

  if((bigint_digit_length(b->x, NUMWORDS) == 0)
     && (bigint_digit_length(b->z, NUMWORDS) == 0)
     && (bigint_digit_length(b->y, NUMWORDS) == 1) && (b->y[0] == 1)) {
    bigint_copy(c->x, a->x, NUMWORDS);
    bigint_copy(c->y, a->y, NUMWORDS);
    bigint_copy(c->z, a->z, NUMWORDS);
    return;
  }

  if((bigint_digit_length(c->x, NUMWORDS) == 0)
     && (bigint_digit_length(c->z, NUMWORDS) == 0)
     && (bigint_digit_length(c->y, NUMWORDS) == 1) && (c->y[0] == 1)) {
    bigint_copy(b->x, a->x, NUMWORDS);
    bigint_copy(b->y, a->y, NUMWORDS);
    bigint_copy(b->z, a->z, NUMWORDS);
    return;
  }

  bigint_mod_multiply(u, c->y, b->z, p, NUMWORDS, NUMWORDS);
  bigint_mod_multiply(aux1, b->y, c->z, p, NUMWORDS, NUMWORDS);
  bigint_mod_substract(u, u, aux1, p, NUMWORDS);

  bigint_mod_multiply(v, c->x, b->z, p, NUMWORDS, NUMWORDS);
  bigint_mod_multiply(aux1, b->x, c->z, p, NUMWORDS, NUMWORDS);
  bigint_mod_substract(v, v, aux1, p, NUMWORDS);

  if(bigint_digit_length(u, NUMWORDS) != 0) {
    if(bigint_digit_length(v, NUMWORDS) == 0) {
      bigint_null(a->x, NUMWORDS);
      bigint_null(a->y, NUMWORDS);
      bigint_null(a->z, NUMWORDS);
      a->y[0] = 1;
      return;
    } else {
      bigint_mod_square(y3, u, p, NUMWORDS);    //y3 = u^2
      bigint_mod_multiply(aux1, y3, b->z, p, NUMWORDS, bigint_digit_length(b->z, NUMWORDS));    //aux1 = z1*u^2
      bigint_mod_square(z3, v, p, NUMWORDS);    //z3 = v^2
      bigint_mod_multiply(aux2, b->x, z3, p, NUMWORDS, NUMWORDS);       //aux2=x1*v^2
      bigint_mod_add(aux2, aux2, aux2, p, NUMWORDS);    //aux2=2*x1*v^2
      bigint_mod_substract(aux1, aux1, aux2, p, NUMWORDS);      //aux1=z1*u^2-2*x1*v^2
      bigint_mod_multiply(aux1, aux1, c->z, p, NUMWORDS, bigint_digit_length(c->z, NUMWORDS));  //aux1 = z2*(z1*u^2-2*x1*v^2)
      bigint_mod_multiply(aux2, z3, v, p, NUMWORDS, NUMWORDS);  //aux2=v^3
      bigint_mod_substract(aux1, aux1, aux2, p, NUMWORDS);      //aux1 = z2*(z1*u^2-2*x1*v^2) - v^3
      bigint_mod_multiply(x3, v, aux1, p, NUMWORDS, NUMWORDS);  //x3 = v*(z2*(z1*u^2-2*x1*v^2) - v^3)

      bigint_mod_multiply(y3, y3, u, p, NUMWORDS, NUMWORDS);    //y3=u^3
      bigint_mod_multiply(y3, y3, b->z, p, NUMWORDS, bigint_digit_length(b->z, NUMWORDS));      // y3 = z1*u^3
      bigint_null(aux1, NUMWORDS);
      aux1[0] = 3;
      bigint_mod_multiply(aux1, b->x, aux1, p, NUMWORDS, 1);    //aux1 = 3*x1
      bigint_mod_multiply(aux1, aux1, u, p, NUMWORDS, NUMWORDS);        //aux1 = 3*x1*u
      bigint_mod_multiply(aux1, aux1, z3, p, NUMWORDS, NUMWORDS);       //aux1 = 3*x1*u*v^2
      bigint_mod_multiply(z3, z3, v, p, NUMWORDS, NUMWORDS);    //z3 = v^3
      bigint_mod_multiply(aux2, b->y, z3, p, NUMWORDS, NUMWORDS);       //aux2 = y1*v^3
      bigint_mod_add(aux2, aux2, y3, p, NUMWORDS);      //aux2 = y1*v^3 + z1*u^3
      bigint_mod_substract(y3, aux1, aux2, p, NUMWORDS);        //y3 = 3*x1*u*v^2 - (y1*v^3 + z1*u^3)
      bigint_mod_multiply(y3, y3, c->z, p, NUMWORDS, bigint_digit_length(c->z, NUMWORDS));      //y3 = z2*(3*x1*u*v^2 - (y1*v^3 + z1*u^3))
      bigint_mod_multiply(aux1, u, z3, p, NUMWORDS, NUMWORDS);  //aux1 = u*v^3
      bigint_mod_add(y3, y3, aux1, p, NUMWORDS);        //y3 = z2*(3*x1*u*v^2 - (y1*v^3 + z1*u^3)) + u*v^3

      bigint_mod_multiply(z3, z3, b->z, p, NUMWORDS,
                          bigint_digit_length(b->z, NUMWORDS));
      bigint_mod_multiply(z3, z3, c->z, p, NUMWORDS,
                          bigint_digit_length(c->z, NUMWORDS));
    }
  } else {
    bigint_mod_square(u, b->z, p, NUMWORDS);    // u = w = z1^2
    bigint_mod_multiply(u, a_c, u, p, NUMWORDS, NUMWORDS);      //w = a*z1^2
    bigint_null(v, NUMWORDS);
    v[0] = 3;
    bigint_mod_square(aux1, b->x, p, NUMWORDS); //aux1 = x1^2
    bigint_mod_multiply(aux1, aux1, v, p, NUMWORDS, 1); //aux1 = 3*x1^2
    bigint_mod_add(u, u, aux1, p, NUMWORDS);    //w = 3*x1^2 + a*z1^2
    bigint_mod_square(v, u, p, NUMWORDS);       //v = w^2
    bigint_mod_multiply(z3, b->y, b->z, p, NUMWORDS, NUMWORDS); // z3= y1*z1
    bigint_mod_add(z3, z3, z3, p, NUMWORDS);    //z3 = 2*y1*z1
    bigint_mod_multiply(aux1, z3, b->y, p, NUMWORDS, NUMWORDS); //aux1 = 2*y1^2*z1
    aux2[0] = 4;                // Can change?
    bigint_mod_multiply(aux1, aux1, aux2, p, NUMWORDS, 1);      //aux1 = 8*y1^2*z1
    bigint_mod_multiply(aux1, aux1, b->x, p, NUMWORDS, NUMWORDS);       //aux1 = 8*x1*y1^2*z1
    bigint_mod_substract(x3, v, aux1, p, NUMWORDS);     //x3 = w^2 - 8*x1*y1^2*z1
    bigint_mod_multiply(x3, x3, z3, p, NUMWORDS, NUMWORDS);     //x3 = 2*y1*z1*(w^2 - 8*x1*y1^2*z1)

    bigint_mod_multiply(aux1, z3, b->y, p, NUMWORDS, NUMWORDS); //aux1 = 2*y1^2*z1
    aux2[0] = 3;
    bigint_mod_multiply(v, u, aux2, p, NUMWORDS, 1);    //v=3*w
    bigint_mod_multiply(v, v, b->x, p, NUMWORDS, NUMWORDS);     //v=3*w*x1
    bigint_mod_substract(y3, v, aux1, p, NUMWORDS);     //y3=3*w*x1-2*y1^2*z1
    bigint_mod_multiply(y3, y3, aux1, p, NUMWORDS, NUMWORDS);   // y3 = 2*y1^2*z1*(3*w*x1-2*y1^2*z1)
    bigint_mod_add(y3, y3, y3, p, NUMWORDS);    // y3 = 4*y1^2*z1*(3*w*x1-2*y1^2*z1)
    power_mod(u, u, 3, NUMWORDS, p, NUMWORDS);  //u = w^3
    bigint_mod_substract(y3, y3, u, p, NUMWORDS);       // y3 = 4*y1^2*z1*(3*w*x1-2*y1^2*z1) - w^3

    power_mod(z3, z3, 3, NUMWORDS, p, NUMWORDS);        // z3 = (2*y1*z1)^3
  }

  bigint_copy(x3, a->x, NUMWORDS);
  bigint_copy(y3, a->y, NUMWORDS);
  bigint_copy(z3, a->z, NUMWORDS);
}

void
ecc_scalar_multiplication_homo(ecc_point_a * R, ecc_point_a * a, u_word * k,
                               u_byte digitsk, u_word * p, u_word * a_c)
{

  u_byte i, j;

  ecc_point_p aux, res;

  bigint_copy(a->x, aux.x, NUMWORDS);
  bigint_copy(a->y, aux.y, NUMWORDS);
  bigint_null(aux.z, NUMWORDS);
  aux.z[0] = 1;

  bigint_null(res.x, NUMWORDS);
  bigint_null(res.y, NUMWORDS);
  bigint_null(res.z, NUMWORDS);
  res.y[0] = 1;

  for(i = 0; i < (digitsk - 1); i++) {
    for(j = 0; j < BIGINT_WORD_BITS; j++) {
      if((k[i] >> j) & 1) {
        ecc_homogeneous_add(&res, &res, &aux, p, a_c);
      }
      ecc_homogeneous_add(&aux, &aux, &aux, p, a_c);
    }
  }

  i = digitsk - 1;
  for(j = 0; j < bigint_bit_length(&k[i], 1); j++) {
    if((k[i] >> j) & 1) {
      ecc_homogeneous_add(&res, &res, &aux, p, a_c);
    }
    ecc_homogeneous_add(&aux, &aux, &aux, p, a_c);
  }

  bigint_modular_inverse(aux.z, res.z, p, NUMWORDS);

  bigint_mod_multiply(R->x, res.x, aux.z, p, NUMWORDS, NUMWORDS);
  bigint_mod_multiply(R->y, res.y, aux.z, p, NUMWORDS, NUMWORDS);
}

void
ecc_jacobian_double(ecc_point_p * a, ecc_point_p * b, u_word * p,
                    u_word * a_c)
{

  u_word T1[NUMWORDS], T2[NUMWORDS], T3[NUMWORDS], T4[NUMWORDS], T5[NUMWORDS];

  bigint_copy(b->x, T1, NUMWORDS);
  bigint_copy(b->y, T2, NUMWORDS);
  bigint_copy(b->z, T3, NUMWORDS);

  if(bigint_is_zero(T2, NUMWORDS) || bigint_is_zero(T3, NUMWORDS)) {
    bigint_null(a->x, NUMWORDS);
    bigint_null(a->y, NUMWORDS);
    bigint_null(a->z, NUMWORDS);
    a->x[0] = 1;
    a->y[0] = 1;
    return;
  }

  bigint_copy(a_c, T4, NUMWORDS);
  bigint_mod_square(T5, T3, p, NUMWORDS);
  bigint_mod_square(T5, T5, p, NUMWORDS);
  bigint_mod_multiply(T5, T4, T5, p, NUMWORDS, NUMWORDS);
  bigint_mod_square(T4, T1, p, NUMWORDS);
  T3[0] = 3;                    //T3 is z1, using last digit
  bigint_mod_multiply(T4, T4, T3, p, NUMWORDS, 1);
  T3[0] = b->z[0];              //Setting last digit of T3 back to the value
  bigint_mod_add(T4, T4, T5, p, NUMWORDS);

  bigint_mod_multiply(T3, T2, T3, p, NUMWORDS, NUMWORDS);
  bigint_mod_add(T3, T3, T3, p, NUMWORDS);
  bigint_copy(T3, a->z, NUMWORDS);      //Z3 computed
  bigint_mod_square(T2, T2, p, NUMWORDS);
  bigint_mod_multiply(T5, T1, T2, p, NUMWORDS, NUMWORDS);
  bigint_mod_add(T5, T5, T5, p, NUMWORDS);
  bigint_mod_add(T5, T5, T5, p, NUMWORDS);
  bigint_mod_square(T1, T4, p, NUMWORDS);
  bigint_mod_add(T3, T5, T5, p, NUMWORDS);
  bigint_mod_substract(T1, T1, T3, p, NUMWORDS);
  bigint_copy(T1, a->x, NUMWORDS);      //X3 computed
  bigint_mod_square(T2, T2, p, NUMWORDS);
  T3[0] = 8;
  bigint_mod_multiply(T2, T2, T3, p, NUMWORDS, 1);
  bigint_mod_substract(T5, T5, T1, p, NUMWORDS);
  bigint_mod_multiply(T5, T4, T5, p, NUMWORDS, NUMWORDS);
  bigint_mod_substract(T2, T5, T2, p, NUMWORDS);
  bigint_copy(T2, a->y, NUMWORDS);
}

void
ecc_jacobian_add(ecc_point_p * a, ecc_point_p * b, ecc_point_p * c,
                 u_word * p, u_word * a_c)
{

  u_word T1[NUMWORDS], T2[NUMWORDS], T3[NUMWORDS], T4[NUMWORDS], T5[NUMWORDS],
    T6[NUMWORDS], T7[NUMWORDS];

  if((bigint_digit_length(b->x, NUMWORDS) == 1) && (b->x[0] == 1)
     && (bigint_digit_length(b->y, NUMWORDS) == 1) && (b->y[0] == 1)
     && (bigint_digit_length(b->z, NUMWORDS) == 0)) {
    bigint_copy(c->x, a->x, NUMWORDS);
    bigint_copy(c->y, a->y, NUMWORDS);
    bigint_copy(c->z, a->z, NUMWORDS);
    return;
  }

  if((bigint_digit_length(c->x, NUMWORDS) == 1) && (c->x[0] == 1)
     && (bigint_digit_length(c->y, NUMWORDS) == 1) && (c->y[0] == 1)
     && (bigint_digit_length(c->z, NUMWORDS) == 0)) {
    bigint_copy(b->x, a->x, NUMWORDS);
    bigint_copy(b->y, a->y, NUMWORDS);
    bigint_copy(b->z, a->z, NUMWORDS);
    return;
  }

  bigint_copy(b->x, T1, NUMWORDS);
  bigint_copy(b->y, T2, NUMWORDS);
  bigint_copy(b->z, T3, NUMWORDS);
  bigint_copy(c->x, T4, NUMWORDS);
  bigint_copy(c->y, T5, NUMWORDS);

  if(c->z[0] != 1 || !bigint_is_zero(&c->z[1], NUMWORDS - 1)) {
    bigint_copy(c->z, T6, NUMWORDS);
    bigint_mod_square(T7, T6, p, NUMWORDS);
    bigint_mod_multiply(T1, T1, T7, p, NUMWORDS, NUMWORDS);
    bigint_mod_multiply(T7, T6, T7, p, NUMWORDS, NUMWORDS);
    bigint_mod_multiply(T2, T2, T7, p, NUMWORDS, NUMWORDS);
  }

  bigint_mod_square(T7, T3, p, NUMWORDS);
  bigint_mod_multiply(T4, T4, T7, p, NUMWORDS, NUMWORDS);
  bigint_mod_multiply(T7, T3, T7, p, NUMWORDS, NUMWORDS);
  bigint_mod_multiply(T5, T5, T7, p, NUMWORDS, NUMWORDS);
  bigint_mod_substract(T4, T1, T4, p, NUMWORDS);
  bigint_mod_substract(T5, T2, T5, p, NUMWORDS);
  if(bigint_is_zero(T4, NUMWORDS)) {
    if(bigint_is_zero(T5, NUMWORDS)) {
      bigint_null(a->x, NUMWORDS);
      bigint_null(a->y, NUMWORDS);
      bigint_null(a->z, NUMWORDS);
    } else {
      bigint_null(a->x, NUMWORDS);
      bigint_null(a->y, NUMWORDS);
      bigint_null(a->z, NUMWORDS);
      a->x[0] = 1;
      a->y[0] = 1;
    }
    return;
  }

  bigint_mod_add(T7, T1, T1, p, NUMWORDS);
  bigint_mod_substract(T1, T7, T4, p, NUMWORDS);
  bigint_mod_add(T7, T2, T2, p, NUMWORDS);
  bigint_mod_substract(T2, T7, T5, p, NUMWORDS);

  if(c->z[0] != 1 || !bigint_is_zero(&c->z[1], NUMWORDS - 1)) {
    bigint_mod_multiply(T3, T3, T6, p, NUMWORDS, NUMWORDS);
  }

  bigint_mod_multiply(T3, T3, T4, p, NUMWORDS, NUMWORDS);
  bigint_copy(T3, a->z, NUMWORDS);
  bigint_mod_square(T7, T4, p, NUMWORDS);
  bigint_mod_multiply(T4, T4, T7, p, NUMWORDS, NUMWORDS);
  bigint_mod_multiply(T7, T1, T7, p, NUMWORDS, NUMWORDS);
  bigint_mod_square(T1, T5, p, NUMWORDS);
  bigint_mod_substract(T1, T1, T7, p, NUMWORDS);
  bigint_copy(T1, a->x, NUMWORDS);
  bigint_mod_add(T1, T1, T1, p, NUMWORDS);
  bigint_mod_substract(T7, T7, T1, p, NUMWORDS);
  bigint_mod_multiply(T5, T5, T7, p, NUMWORDS, NUMWORDS);
  bigint_mod_multiply(T4, T2, T4, p, NUMWORDS, NUMWORDS);
  bigint_mod_substract(T2, T5, T4, p, NUMWORDS);
  bigint_mod_dividebypow2(T2, T2, 1, p, NUMWORDS);

  bigint_copy(T2, a->y, NUMWORDS);
}

void
ecc_scalar_multiplication_jacob(ecc_point_a * R, ecc_point_a * a, u_word * k,
                                u_byte digitsk, u_word * p, u_word * a_c)
{

  u_byte i, j;

  ecc_point_p N, res;

  bigint_copy(a->x, N.x, NUMWORDS);
  bigint_copy(a->y, N.y, NUMWORDS);
  bigint_null(N.z, NUMWORDS);
  N.z[0] = 1;

  bigint_null(res.x, NUMWORDS);
  bigint_null(res.y, NUMWORDS);
  bigint_null(res.z, NUMWORDS);
  res.x[0] = 1;
  res.y[0] = 1;

  for(i = 0; i < (digitsk - 1); i++) {
    for(j = 0; j < BIGINT_WORD_BITS; j++) {
      if((k[i] >> j) & 1) {
        ecc_jacobian_add(&res, &res, &N, p, a_c);
      }
      ecc_jacobian_double(&N, &N, p, a_c);
    }
  }

  i = digitsk - 1;
  for(j = 0; j < bigint_bit_length(&k[i], 1); j++) {
    if((k[i] >> j) & 1) {
      ecc_jacobian_add(&res, &res, &N, p, a_c);
    }
    ecc_jacobian_double(&N, &N, p, a_c);
  }

  bigint_mod_square(N.z, res.z, p, NUMWORDS);

  bigint_modular_inverse(N.z, N.z, p, NUMWORDS);

  bigint_mod_multiply(R->x, res.x, N.z, p, NUMWORDS, NUMWORDS);

  power_mod(N.z, res.z, 3, NUMWORDS, p, NUMWORDS);

  bigint_modular_inverse(N.z, N.z, p, NUMWORDS);

  bigint_mod_multiply(R->y, res.y, N.z, p, NUMWORDS, NUMWORDS); //Jacobian

}

void
ecc_scalar_multiplication_ltr_jacob(ecc_point_a * R, ecc_point_a * a,
                                    u_word * k, u_byte digitsk, u_word * p,
                                    u_word * a_c)
{

  int8_t i, j;

  ecc_point_p N, res;

  if (bigint_is_zero(k, NUMWORDS)){ // k needs to be different than 0
  	return;
  }

  bigint_copy(a->x, N.x, NUMWORDS);
  bigint_copy(a->y, N.y, NUMWORDS);
  bigint_null(N.z, NUMWORDS);
  N.z[0] = 1;

  bigint_null(res.x, NUMWORDS);
  bigint_null(res.y, NUMWORDS);
  bigint_null(res.z, NUMWORDS);
  res.x[0] = 1;
  res.y[0] = 1;

  for(j = bigint_bit_length(&k[digitsk - 1], 1) - 1; j >= 0; j--) {
    ecc_jacobian_double(&res, &res, p, a_c);
    if((k[digitsk - 1] >> j) & 1) {
      ecc_jacobian_add(&res, &res, &N, p, a_c);
    }
  }

  for(i = digitsk - 2; i >= 0; i--) {
    for(j = BIGINT_WORD_BITS - 1; j >= 0; j--) {
      ecc_jacobian_double(&res, &res, p, a_c);
      if((k[i] >> j) & 1) {
        ecc_jacobian_add(&res, &res, &N, p, a_c);
      }
    }
  }

  bigint_mod_square(N.z, res.z, p, NUMWORDS);

  bigint_modular_inverse(N.z, N.z, p, NUMWORDS);

  bigint_mod_multiply(R->x, res.x, N.z, p, NUMWORDS, NUMWORDS);

  power_mod(N.z, res.z, 3, NUMWORDS, p, NUMWORDS);

  bigint_modular_inverse(N.z, N.z, p, NUMWORDS);

  bigint_mod_multiply(R->y, res.y, N.z, p, NUMWORDS, NUMWORDS); //Jacobian

}
#ifdef HW_ECC
void 
ecc_aff_hw_add(ecc_point_a * a, ecc_point_a * b, ecc_point_a * c,
                    u_word * p, u_word * a_c)
{
  /* Initialize varibles used by the PKA module*/
  tECPt hw_a, hw_b, hw_c;
  uint32_t resultVector;
  resultVector = 0;
  
  hw_a.pui32X = (uint32_t *) a->x;
  hw_a.pui32Y = (uint32_t *) a->y;
  
  hw_b.pui32X = (uint32_t *) b->x;
  hw_b.pui32Y = (uint32_t *) b->y;
  
  hw_c.pui32X = (uint32_t *) c->x;
  hw_c.pui32Y = (uint32_t *) c->y;
  
  uint8_t pka_status;
  
  /* Wait for the PKA driver to become available */
  do {} while(PKAGetOpsStatus() == PKA_STATUS_OPERATION_INPRG);
  
  pka_status = PKAECCAddStart(&hw_b,&hw_c, &hw_curve_param,&resultVector);
  DBG_PRINT("ECC HW Add start status %u\n", pka_status);

  do {} while(PKAGetOpsStatus() == PKA_STATUS_OPERATION_INPRG);

  if(pka_status == PKA_STATUS_SUCCESS){
    pka_status = PKAECCAddGetResult(&hw_a,resultVector);
  }
  DBG_PRINT("ECC HW Add end status %u\n", pka_status);
  
}

void
ecc_scalar_multiplication_hw(ecc_point_a * R, ecc_point_a * a, u_word * k,
                               u_byte digitsk, u_word * p, u_word * a_c)
{
  tECPt hw_R, hw_a;
  uint32_t resultVector;
  resultVector = 0;
  
  hw_R.pui32X = (uint32_t *) R->x;
  hw_R.pui32Y = (uint32_t *) R->y;
  
  hw_a.pui32X = (uint32_t *) a->x;
  hw_a.pui32Y = (uint32_t *) a->y;
  
  
  uint8_t pka_status;
  
  /* Wait for the PKA driver to become available */
  do {} while(PKAGetOpsStatus() == PKA_STATUS_OPERATION_INPRG);
  
  pka_status = PKAECCMultiplyStart(k,&hw_a, &hw_curve_param, &resultVector);
  DBG_PRINT("ECC HW mul start status %u\n", pka_status);

  do {} while(PKAGetOpsStatus() == PKA_STATUS_OPERATION_INPRG);

  if(pka_status == PKA_STATUS_SUCCESS){
    pka_status = PKAECCMultiplyGetResult(&hw_R,resultVector);
  }
  DBG_PRINT("ECC HW mul end status %u\n", pka_status);
}

#endif /* HW_ECC */

u_word
getbits(u_word * b, u_byte position, u_byte num_bits, u_byte digits)
{
  u_word aux[2];

  if(position / BIGINT_WORD_BITS > 0) {
    bigint_copy(&b[position / BIGINT_WORD_BITS - 1], aux, 2);
  } else {
    aux[1] = b[0];
  }

  bigint_shift_bits_right(aux,
                          BIGINT_WORD_BITS - num_bits +
                          position % BIGINT_WORD_BITS + 1, 2);
  //PROVISIONAL
  aux[0] = aux[0] & ((1 << (num_bits)) - 1);
  //bigint_shift_bits_left(aux,BIGINT_WORD_BITS-num_bits,1);
  //bigint_shift_bits_right(aux,BIGINT_WORD_BITS-num_bits,1);
  return aux[0];
}

void
ecc_generate_private_key(u_word * secr)
{
#ifdef STATIC_ECC_KEY
  secr[0] = 0xd2ac0cf1;
  secr[1] = 0xc146d4ce;
  secr[2] = 0x910f4d15;
  secr[3] = 0x8960d7bf;
  secr[4] = 0x844896d4;
  secr[5] = 0xebffcdbe;
#else
  u_byte i;

  do {
#ifdef WORDS_32_BITS
    for(i = 0; i < NUMWORDS; i++) {
      secr[i] = (u_word) (random_rand() << 16);
      secr[i] |= random_rand();
    }
#endif /* WORDS_32_BITS */

#ifdef WORDS_16_BITS
    for(i = 0; i < NUMWORDS; i++) {
      secr[i] = random_rand();
    }
#endif /* WORDS_16_BITS */
  } while(bigint_compare(secr, param.p, NUMWORDS) >= 0);

#endif /* STATIC_ECC_KEY */
  if(DEBUG) {
    DBG_PRINT("Secret key:\n");
    bigint_print(secr, NUMWORDS);
  }

}

void
ecc_generate_public_key(u_word * secr, ecc_point_a * publ)
{
#ifdef STATIC_ECC_KEY
  /* Only for 192 bit key */
  publ->x[0] = 0xde93f79c;
  publ->x[1] = 0x740eac8e;
  publ->x[2] = 0xf2e587fe;
  publ->x[3] = 0x6fd6f3a8;
  publ->x[4] = 0xf141e405;
  publ->x[5] = 0xef5c6f62;

  publ->y[0] = 0x5e11e2d4;
  publ->y[1] = 0x7db6733d;
  publ->y[2] = 0x30fa5b3e;
  publ->y[3] = 0x45723b39;
  publ->y[4] = 0xa19914c5;
  publ->y[5] = 0xd882be92;
#else
#ifdef HW_ECC
  ecc_scalar_multiplication_hw(publ, &param.point, secr, NUMWORDS,
                                      param.p, param.curve.a);
#else
#ifdef AFFINE_COORDINATES
  ecc_aff_scalar_multiplication(publ, &param.point, secr, NUMWORDS, 
                                      param.p, param.curve.a);
#elif HOMOGENEOUS_COORDINATES
  ecc_scalar_multiplication_homo(publ, &param.point, secr, NUMWORDS,
                                      param.p, param.curve.a);
#elif JACOBIAN_COORDINATES
  ecc_scalar_multiplication_ltr_jacob(publ, &param.point, secr, NUMWORDS,
                                      param.p, param.curve.a);
#endif /* JACOBIAN_COORDINATES */
#endif /* HW_ECC */
#endif /* STATIC_ECC_KEY */
  if(DEBUG) {
    DBG_PRINT("Public key:\n");
    bigint_print(publ->x, NUMWORDS);
    bigint_print(publ->y, NUMWORDS);
  }
  
}

#ifdef COMPACT_COORDINATES      
uint8_t
ecc_generate_shared_key(u_word * shar, u_word * secr, u_word * publx)
{

  ecc_point_a aux;

  bigint_copy(publx, aux.x, NUMWORDS);

  bigint_generate_full_point_from_x(aux, param);

  if (ecc_check_point(publ, param)==0){
    DBG_PRINT("DOES NOT BELONG TO CURVE\n");
    return 0;
  }

#ifdef HW_ECC
  ecc_scalar_multiplication_hw(&aux, &aux, secr, NUMWORDS, 
                                    param.p, param.curve.a);
#else
#ifdef AFFINE_COORDINATES
  ecc_aff_scalar_multiplication(&aux, &aux, secr, NUMWORDS, 
                                    param.p, param.curve.a);
#elif HOMOGENEOUS_COORDINATES
  ecc_scalar_multiplication_homo(&aux, &aux, secr, NUMWORDS,
                                    param.p, param.curve.a);
#elif JACOBIAN_COORDINATES
  ecc_scalar_multiplication_ltr_jacob(&aux, &aux, secr, NUMWORDS, 
                                    param.p, param.curve.a);
#endif /* JACOBIAN_COORDINATES */
#endif /* HW_ECC */
  
  return 1;
}

#else
uint8_t
ecc_generate_shared_key(u_word * shared, u_word * secr, ecc_point_a * publ)
{
  ecc_point_a res;

  if (ecc_check_point(publ)==0){
    return 0;
  }
  
#ifdef HW_ECC
  ecc_scalar_multiplication_hw(&res, publ, secr, NUMWORDS, 
                                      param.p, param.curve.a);
#else
#ifdef AFFINE_COORDINATES
  ecc_aff_scalar_multiplication(&res, publ, secr, NUMWORDS, 
                                      param.p, param.curve.a);
#elif HOMOGENEOUS_COORDINATES
  ecc_scalar_multiplication_homo(&res, publ, secr, NUMWORDS,
                                      param.p, param.curve.a);
#elif JACOBIAN_COORDINATES
  ecc_scalar_multiplication_ltr_jacob(&res, publ, secr, NUMWORDS,
                                      param.p, param.curve.a);
#endif /* JACOBIAN_COORDINATES */
#endif /* HW_ECC */ 
  
// Returns shared DH result
  bigint_copy(res.x, shared, NUMWORDS);
  return 1;
}
#endif /* COMPACT_COORDINATES */

void
ecc_generate_signature_from_sha(u_word * secr, u_word * e,
                       u_word * signature, u_word * rx)
{
  u_byte i;
  u_word k[NUMWORDS];
  ecc_point_a r;
  
  do {
#ifdef WORDS_32_BITS
    for(i = 0; i < NUMWORDS; i++) {
      k[i] = (u_word) (random_rand() << 16);
      k[i] |= random_rand();
    }
#endif /* WORDS_32_BITS */

#ifdef WORDS_16_BITS
    for(i = 0; i < NUMWORDS; i++) {
      k[i] = random_rand();
    }
#endif /* WORDS_16_BITS */
  } while(bigint_compare(k, param.order, NUMWORDS) >= 0);

#ifdef HW_ECC
  ecc_scalar_multiplication_hw(&r, &param.point, k, NUMWORDS, 
                                     param.p, param.curve.a);
#else
#ifdef AFFINE_COORDINATES
  ecc_aff_scalar_multiplication(&r, &param.point, k, NUMWORDS, 
                                      param.p, param.curve.a);
#elif HOMOGENEOUS_COORDINATES
  ecc_scalar_multiplication_homo(&r, &param.point, k, NUMWORDS,
                                      param.p, param.curve.a);
#elif JACOBIAN_COORDINATES
  ecc_scalar_multiplication_ltr_jacob(&r, &param.point, k, NUMWORDS,
                                      param.p, param.curve.a);
#endif /* JACOBIAN_COORDINATES */
#endif /* HW_ECC */
  
  bigint_amodb(rx, r.x, param.order, NUMWORDS, NUMWORDS);
  bigint_mod_multiply(signature, secr, rx, param.order, NUMWORDS, NUMWORDS);
  bigint_mod_add(signature, signature, e, param.order, NUMWORDS);
  bigint_modular_inverse(e, k, param.order, NUMWORDS);
  bigint_mod_multiply(signature, signature, e, param.order, NUMWORDS, NUMWORDS);
}

uint8_t
ecc_check_signature_from_sha(ecc_point_a * public, u_word * e,
                    u_word * signature, u_word * r)
{
  u_word u1[NUMWORDS], u2[NUMWORDS];
  ecc_point_a res, aux1;
  
  bigint_modular_inverse(u2, signature, param.order, NUMWORDS);

  bigint_mod_multiply(u1, u2, e, param.order, NUMWORDS, NUMWORDS);

  bigint_mod_multiply(u2, u2, r, param.order, NUMWORDS, NUMWORDS);

#ifdef HW_ECC
  ecc_scalar_multiplication_hw(&aux1, &param.point, u1, NUMWORDS,
                                          param.p, param.curve.a);
  ecc_scalar_multiplication_hw(&res, public, u2, NUMWORDS,
                                          param.p, param.curve.a); 
#else
#ifdef AFFINE_COORDINATES
  ecc_aff_scalar_multiplication(&aux1, &param.point, u1, NUMWORDS,
                                          param.p, param.curve.a);
  ecc_aff_scalar_multiplication(&res, public, u2, NUMWORDS,
                                          param.p, param.curve.a);
#elif HOMOGENEOUS_COORDINATES
  ecc_scalar_multiplication_homo(&aux1, &param.point, u1, NUMWORDS,
                                          param.p, param.curve.a);
  ecc_scalar_multiplication_homo(&res, public, u2, NUMWORDS,
                                          param.p, param.curve.a);
#elif JACOBIAN_COORDINATES
  ecc_scalar_multiplication_ltr_jacob(&aux1, &param.point, u1, NUMWORDS,
                                      param.p, param.curve.a);
  ecc_scalar_multiplication_ltr_jacob(&res, public, u2, NUMWORDS, param.p,
                                      param.curve.a);
#endif /* JACOBIAN_COORDINATES */
#endif /* HW_ECC */
  
#ifdef HW_ECC
  ecc_aff_hw_add(&res, &aux1, &res, param.p, param.curve.a);
#else 
  ecc_affine_add(&res, &aux1, &res, param.p, param.curve.a);
#endif
  if(bigint_compare(res.x, r, NUMWORDS) == 0) {
    DBG_PRINT("Valid signature\n");
    return 0;
  } else {
    DBG_PRINT("Invalid signature, rejected\n");
    return -1;
  }
}

uint32_t
ecc_check_point(ecc_point_a * point)
{
  u_word aux[NUMWORDS], aux2[NUMWORDS];

  power_mod(aux, point->x, 3, NUMWORDS, param.p, NUMWORDS);
  bigint_mod_multiply(aux2, point->x, param.curve.a, param.p, NUMWORDS,
                      NUMWORDS);
  bigint_mod_add(aux, aux, aux2, param.p, NUMWORDS);
  bigint_mod_add(aux, aux, param.curve.b, param.p, NUMWORDS);

  bigint_mod_square_root(aux, aux, param.p, NUMWORDS);

  bigint_mod_substract(aux2, param.p, aux, param.p, NUMWORDS);

  if((!bigint_compare(aux, point->y, NUMWORDS))
     || (!bigint_compare(aux2, point->y, NUMWORDS))) {
    DBG_PRINT("The point belongs to the curve\n");
    return 1;
  } else {
    DBG_PRINT("The point doesn't belong to the curve\n");
    return 0;
  }

}
