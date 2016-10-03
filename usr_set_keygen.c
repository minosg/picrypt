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

/* Common custom anti-tamper routine */
bool usr_anti_tamper(hw_msg_page_t * hwinfo)
{
  const bool antitamper = _USRST_ANTI_TAMPER_;

  if (antitamper == true) {
    printf("Anti-Tamper Warning: \n");
    printf("Password: %u\n", PI_DIGITS);

    /* if code does not exit here it will expose the buffers to debuggers.*/
    exit(0);
    /* If debugger jumps over the exit call, return a fake number */
    return true;
  }

  const bool authorized = _USRST_AUTHORIZED_;

  /* Program will NOT break execution when it runs on Unauthorized hardware.
  It is REQUIRED for the user to catch the authorized and mess with the
  algorythm producing the key. Having no feedback on weather a key is valid or
  not makes it harder for bruteforce attack to work*/

  if (authorized != true) {
    printf("Not Authorized\n");
    return true;
  }
  return false;
}

/* Calculate the low bits of the hash */
uint64_t hash_low(hw_msg_page_t * hwinfo)
{
  /* Uncomment any of the fields that you need to calcuate the hash key
  const bool authorized = *(bool *)hw_get(hwinfo, HW_AUTHORIZED);
  const bool anti-tamper = *(bool *)hw_get(hwinfo, HW_ANTITAMPER);
  const uint64_t serial = *(uint64_t *)hw_get(hwinfo, HW_SERIAL);
  const char *machine_id = (char *)hw_get(hwinfo, HW_MACHINE_ID);
  const char *sha =  (char *)hw_get(hwinfo, HW_SHA1);*/

  /* Or use equivalent macros
  const bool authorized = _USRST_AUTHORIZED_;
  const bool anti-tamper =  _USRST_ANTI_TAMPER_;
  const uint64_t serial = _USRST_SERIAL_ ;
  const char *machine_id = _USRST_MACHINEID_;
  const char *sha =  _USRST_SHA1_;
  */

  uint64_t ret = 0;

  if (usr_anti_tamper(hwinfo) == true) {
    printf("Not Authorized\n");
    ret = (uint64_t)(PI_DIGITS);
  } else {
    /* Print user input if set */
    const char *input = _USRST_UINPT_;
    if (input != NULL) printf("User Input %s\n", input);
    /* Insert your own logic here */
    ret = 1;
  }
  return (uint64_t)(ret);
}

/* Calculate the upper bits of the hash (only used when LONG_HASH is defined)*/
uint64_t hash_high(hw_msg_page_t * hwinfo)
{
  uint64_t ret = 0;

  if (usr_anti_tamper(hwinfo) == true) {
    printf("Not Authorized\n");
    ret = (uint64_t)(PI_DIGITS);
  } else {
    /* Insert your own logic here */
    ret = 2;
  }
  return (uint64_t)(ret);
}
