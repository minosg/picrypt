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
 * File Description: Custom User locking routines                             *
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
  const bool *authorized = *(bool *)hwinfo_get_pl(hwinfo, HW_AUTHORIZED);
  const bool anti-tamper = *(bool *)hwinfo_get_pl(hwinfo, HW_ANTITAMPER);
  const uint64_t serial = *(uint64_t *)hwinfo_get_pl(hwinfo, HW_SERIAL);
  const char *machine_id = (char *)hwinfo_get_pl(hwinfo, HW_MACHINE_ID);
  const char *sha =  (char *)hwinfo_get_pl(hwinfo, HW_SHA1);
  */

  const bool antitamper = *(bool *)hwinfo_get_pl(hwinfo, HW_ANTITAMPER);
  if (antitamper == true) {
    printf("Anti-Tamper Warning, there is your fake-serial: \n");
    return (uint64_t)(123);
  }

  uint8_t ret = 1;
  const bool authorized = *(bool *)hwinfo_get_pl(hwinfo, HW_AUTHORIZED);

  /* Program will NOT break execution when it runs on Unauthorized hardware.
  It is REQUIRED for the user to catch the authorized and mess with the
  algorythm producing the key. Having no feedback on weather a key is valid or
  not makes it harder for bruteforce attack to work*/

  if (authorized != true) {
    printf("Not Authorized\n");
    ret = ret << 3;
  }
  return (uint64_t)(ret);
}

/* Calculate the upper bits of the hash (only used when LONG_HASH is defined)*/
uint64_t hash_high(hwd_nfo_param_t * hwinfo){
  return (uint64_t)(2);
}
