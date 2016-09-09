/*****************************************************************************\
 * PiCrpy is a software key generator for ecryptfs locked system.             *
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
#include <inttypes.h>
#include <stdbool.h>
#include "strhide.h"

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

/************************
   Enums
************************/
/**
 * Locl Levels
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
void string_slice_from_file(char *fname,
                            uint32_t offset,
                            uint32_t len,
                            char (*buffer)[]);

/* Copy the software machine id string from file to an initialized buffer */
void soft_machine_id(char (*ret_buff)[]);

/**
 * User Key generation Routine
 *
 * @param serial integer represenation of the PI CPU Serial Number.
 *
 * @return 64Bit Unsigned Integer for the encryption key
 */
uint64_t hash(uint64_t serial);

/**
 * Crate a RAM_FILE containing the hash key
 *
 * @param hash_key Integer representation of the calculated haskhed password.
 *
 */
void ram_key(uint64_t hash_key);

/**
 * Check a hash againist the calcuated hardware hash
 *
 * @param key String hexadecimal represenation of the key to test.
 *
 * @return True if key matches
 */

bool validate_key(char* key);

/**
 * Print Help Menu
 *
 * @param serial integer represenation of the PI CPU Serial Number.
 *
 */
void help(const char* prgm);

#endif /* _PICRYPT_H_ */
