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

uint64_t hash_low(hwd_nfo_param_t * hwinfo)
{
  /* Uncomment any of the fields that you need to calcuate the hash key
  const uint64_t serial = *(uint64_t *)hwinfo_get_pl(hwinfo, HW_SERIAL);
  const char *machine_id = (char *)hwinfo_get_pl(hwinfo, HW_MACHINE_ID);
  const char *sha =  (char *)hwinfo_get_pl(hwinfo, HW_SHA1);
  */
  return (uint64_t)(1);
}
