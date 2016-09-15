/*****************************************************************************\
 * PiCrypt is a software key generator for ecryptfs locked system.            *
 * Since the program is meant to unlock the protected area, it has to be      *
 * decrypted itself but will perform a set of  hardware tests before producing*
 * the unlock key.                                                            *
 *                                                                            *
 * Author: Minos Galanakis                                                    *
 * Email: minos197@gmail.com                                                  *
 * License: GPL v3.0                                                          *
 * Project: PiCrypt                                                           *
 * File Description: Custom User locking routine                              *
 \****************************************************************************/

/* Change the method of calculating the key to YOUR OWN CUSTOM and UNIQUE
method. By defualy it just generates a key equal to the cpu serial, which is
UNSAFE. Esure you maintain the cast to 64Bit unsigned integer before returning
the result of your method */
#include "authorized_hwd.h"
#include "picrypt.h"

/* Calculate the low bits of the hash */
uint64_t hash_low(hwd_nfo_param_t * hwinfo)
{
  /* Uncomment any of the fields that you need to calcuate the hash key
  const uint64_t serial = *(uint64_t *)hwinfo_get_pl(hwinfo, HW_SERIAL);
  const char *machine_id = (char *)hwinfo_get_pl(hwinfo, HW_MACHINE_ID);
  const char *sha =  (char *)hwinfo_get_pl(hwinfo, HW_SHA1);
  */
  return (uint64_t)(1);
}

/* Calculate the upper bits of the hash (only used when LONG_HASH is defined)*/
uint64_t hash_high(hwd_nfo_param_t * hwinfo){
  return (uint64_t)(2);
}

/* Return the hash in printable string format (Do not edit) */
char * hash_str(hwd_nfo_param_t * hwinfo, char * hash_buffer)
{
  uint64_t LB = hash_low(hwinfo);
  #ifdef LONG_HASH
  uint64_t HB = hash_high(hwinfo);
  snprintf(hash_buffer, HBUFF_SZ, "%08" PRIx64 "%08" PRIx64 "", HB, LB);
  #else
  snprintf(hash_buffer, HBUFF_SZ, "%08" PRIx64 "", LB);
  #endif
  return hash_buffer;
}
