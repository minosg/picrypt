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
 * File Description: Main Header File
 \****************************************************************************/

#ifndef _PICRYPT_H_
#define _PICRYPT_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#include "strhide.h"
#include "hwinfo.h"

#define __STDC_FORMAT_MACROS
#define CPU_SER_SIZE    8                 ///< Len of serial in Bytes
#define MACHINE_ID_SIZE 32                ///< Len of machine-id in Bytes
#define PI_DIGITS 3141592653u             ///< Digits of PI as tribute/seed
#define RAM_FILE "/tmp/lock.key"          ///< Location and name of RAM file
#define CPU_FILE "/proc/cpuinfo"          ///< Used in CPU Serial Extraction
#define MACHINE_ID_FILE "/etc/machine-id" ///< Used in SOftware ID Extraction

#if PI_VER == 2
    #define CPU_SER_OFFSET  1103
#else
    #define CPU_SER_OFFSET  1127
#endif

#ifdef LONG_HASH
  #define HBUFF_SZ 16
#else
  #define HBUFF_SZ 8
#endif


/************************
   Enums
************************/
/**
 * Lock Levels
 */
typedef enum lock_level {
  CARE_BEAR     = 0, ///< No Checks
  SCRIPT_KIDDY  = 1, ///< Only CPU Serial Check
  ARCH_USER     = 2, ///< CPU Serial and Software Check
  PEN_TESTER    = 3, ///< CPU Serial, Software, and Random File SHA
  TIN_FOIL_HAT  = 4, ///< Everything and a handrware dongle key
} lock_level_t;

/**
 * Return Status
 */
typedef enum ret_status {
  SUCESS = 0, ///< successfull return
  FAIL   = 1, ///< error
} ret_status_t;


/************************
   Method Declarations
************************/

/**
 * return the CPU Serial for the device
 *
 * @return 64Bit Unsigned Integer Representing PI's serial number
 */
uint64_t pi_serial();

/**
 * Copies a string slice from a file to an initialized buffer
 *
 * @param fname File path to parse for the string.
 * @param offset How many characters to offset the cursor before reading.
 * @param len How many characters to read from offset starting point.
 * @param buffer Pre allocated buffer to store the string slice to.
 *
 * @return 64Bit Unsigned Integer for the encryption key
 */
void string_slice_from_file(char const *fname,
                            const uint32_t offset,
                            const uint32_t len,
                            char *buffer);
/**
 * Copies a the machine id from OS to a buffer
 *
 * @param ret_buff Pre-initialized buffer to copy the machine id into
 *
 */
void soft_machine_id(char *ret_buff);

/**
 * Generate sha1 hash from string input file path
 *
 * @param fname char* buffer that the plain text path is stored.
 * @param string buffer to store the sha1 string.
 *
 * @return pointer to storage string buffer.
 */
char * sha1_from_file(char * fname, char *sha_hash);

/**
 * Generate sha1 hash from filename that is stored in a strhide encoded buffer
 *
 * @param fname int16_t buffer that the encrypted path is stored.
 * @param byte_size Integer size of the buffer in bytes.
 * @param sha_hash buffer to store the sha1 string.
 *
 * @return sha1 string.
 */
char * sha1_from_en_buf(int16_t const *fname,
                        const uint16_t byte_size,
                        char *sha_hash);

/**
 * Check a hash againist the calcuated hardware hash
 *
 * @param fname int16_t buffer that the encrypted path is stored.
 * @param byte_size Integer size of the buffer in bytes.
 * @param sha_buff Output buffer to store the sha1 string in ecnrypted format.
 *
 * @return The sha_buff pointer.
 */
int16_t * sha1_from_en_buf_to_en_buff(int16_t const *fname,
                                      const uint16_t byte_size,
                                      int16_t *sha_buff);

/**
 * User Key generation Routine that returns a string containing the hash
 *
 * @param hwinfo Data structure containing variable hardware information.
 * @param hash_buffer char buffer to store the hash.
 *
 * @return 64Bit Unsigned Integer for the encryption key
 */
char * hash_str(hwd_nfo_param_t * hwinfo, char * hash_buffer);

/**
 * User Key generation Routine that returns a pointer to the encrypted buffer
 * containing the hash
 *
 * @param hwinfo Data structure containing variable hardware information.
 * @param hash_buffer Integer buffer to store the hash in encrypted format.
 *
 * @return uint16_t Pointer to buffer,
 */
int16_t * hash_enc(hwd_nfo_param_t * hwinfo,
                   int16_t * hash_buffer_e,
                   const uint16_t byte_size);

/**
 * Crate a RAM_FILE containing the hash key
 *
 * @param hash_key Integer representation of the calculated haskhed password.
 *
 */

void ram_key(const char * hash_key);

/**
 * Check a hash againist the calcuated hardware hash
 *
 * @param key String hexadecimal represenation of the key to test.
 *
 * @return True if key matches
 */

bool validate_key(char const *key);

/**
 * Print Help Menu
 *
 * @param serial integer represenation of the PI CPU Serial Number.
 *
 */

void help(const char* prgm);


/**
 * User Key generation Routine for the low bits of the hash
 *
 * @param hwinfo Data structure containing variable hardware information.
 *
 * @return 64Bit Unsigned Integer for the encryption key
 */
uint64_t hash_low(hwd_nfo_param_t * hwinfo);

/**
 * User Key generation Routine for the high bits of the hash
 *
 * @param hwinfo Data structure containing variable hardware information.
 *
 * @return 64Bit Unsigned Integer for the encryption key
 */
uint64_t hash_high(hwd_nfo_param_t * hwinfo);

#endif /* _PICRYPT_H_ */
