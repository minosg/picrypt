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
  return false;
}

/* Calculate the low bits of the hash */
char * hash_low(hw_msg_page_t * hwinfo, char * out_buff)
{
  /* Uncomment any of the fields that you need to calcuate the hash key
  const bool authorized = *(bool *)hw_get(hwinfo, HW_AUTHORIZED);
  const bool anti-tamper = *(bool *)hw_get(hwinfo, HW_ANTITAMPER);
  const uint64_t serial = *(uint64_t *)hw_get(hwinfo, HW_SERIAL);
  const char *machine_id = (char *)hw_get(hwinfo, HW_MACHINE_ID);
  const char *sha =  (char *)hw_get(hwinfo, HW_SHA1);
  const char *input = (char *)hw_get(hwinfo, HW_USR_INPUT); */

  /* Or use equivalent macros
  const bool authorized = _USRST_AUTHORIZED_;
  const bool anti-tamper =  _USRST_ANTI_TAMPER_;
  const uint64_t serial = _USRST_SERIAL_ ;
  const char *machine_id = _USRST_MACHINEID_;
  const char *sha =  _USRST_SHA1_;
  const char *input = _USRST_UINPT_;
  */

  uint64_t lock_idx = 0;
  char machine_id_d[9];
  char sha_d[9];
  uint64_t ret = 0;

  if (usr_anti_tamper(hwinfo) == true) {
    printf("Not Authorized\n");
    ret = (uint64_t)(PI_DIGITS);
  } else {

    const uint64_t serial = _USRST_SERIAL_ ;
    const char *machine_id = _USRST_MACHINEID_;
    const char *sha =  _USRST_SHA1_;
    uint64_t machine_id_i, sha_i;

    /* Get user input if set */
    const char *input = _USRST_UINPT_;
    if (input != NULL) printf("User Input %s\n", input);

    /* Get the lock index as a modulo 10 of serial */
    lock_idx = (serial & 0x0000000F) % 10;
    printf("lock_idx %lu\n", lock_idx);
    printf("SHA1 %s\n", sha);

    /* Slice the machine ID and sha to 64 bit buffers */
    snprintf(machine_id_d, 9 ,"%s", machine_id + lock_idx);
    snprintf(sha_d, 9 ,"%s", sha + lock_idx);
    machine_id_i = (uint64_t)strtoull(machine_id_d, NULL, 16);
    sha_i = (uint64_t)strtoull(sha_d, NULL, 16);

    //return (uint64_t)strtoull(ser_buffer, NULL, 16);
    printf("Index %" PRIu64 " X: %" PRIx64 "\n", ret, ret);
    printf("MID: %s SHA: %s\n",machine_id_d ,sha_d );
    printf("MIDx: %" PRIx64 " SHAx: %" PRIx64 "\n",machine_id_i ,sha_i );

    ret = (serial & 0xF0F00000) +
          (machine_id_i & 0x0000F0F0) +
          (sha_i & 0x0F000F00) +
          (PI_DIGITS & 0x000F000F);
  }

  /* Convert it to string after no more math is required */
  snprintf(out_buff, 9, "%08" PRIx64 "", ret);
  return out_buff;
}

/* Calculate the upper bits of the hash (only used when LONG_HASH is defined)*/
char * hash_high(hw_msg_page_t * hwinfo, char * out_buff)
{
  uint64_t lock_idx = 0;
  char machine_id_d[9];
  char sha_d[9];
  uint64_t ret = 0;

  if (usr_anti_tamper(hwinfo) == true) {
    printf("Not Authorized\n");
    ret = (uint64_t)(PI_DIGITS);
  } else {

    const uint64_t serial = _USRST_SERIAL_ ;
    const char *machine_id = _USRST_MACHINEID_;
    const char *sha =  _USRST_SHA1_;
    uint64_t machine_id_i, sha_i;

    /* Get the lock index as a modulo 10 of serial */
    lock_idx = (serial & 0x000000F0) % 10;
    printf("lock_idx %lu\n", lock_idx);
    printf("SHA1 %s\n", sha);

    /* Slice the machine ID and sha to 64 bit buffers */
    snprintf(machine_id_d, 9 ,"%s", machine_id + lock_idx);
    snprintf(sha_d, 9 ,"%s", sha + lock_idx);
    machine_id_i = (uint64_t)strtoull(machine_id_d, NULL, 16);
    sha_i = (uint64_t)strtoull(sha_d, NULL, 16);

    //return (uint64_t)strtoull(ser_buffer, NULL, 16);
    printf("Index %" PRIu64 " X: %" PRIx64 "\n", ret, ret);
    printf("MID: %s SHA: %s\n",machine_id_d ,sha_d );
    printf("MIDx: %" PRIx64 " SHAx: %" PRIx64 "\n",machine_id_i ,sha_i );

    /* Similar to short hash but different bit masks */
    ret = (serial & 0x000FF000) +
          (machine_id_i & 0xF000000F) +
          (sha_i & 0x00F00F00) +
          (PI_DIGITS & 0x0F0000F0);
  }
  /* Convert it to string after no more math is required */
  snprintf(out_buff, 9, "%08" PRIx64 "", ret);
  return out_buff;
}

/* Handle custom user input */
void input_method(hw_msg_page_t * hwinfo,  char * hash) {

  /* Print user input if set */
  const char *input = _USRST_UINPT_;

  if (input != NULL) printf("User Input: %s Hash: %s\n", input, hash);
}
