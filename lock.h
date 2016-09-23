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
 * File Description: Handles System operations related to unlocking           *
 * locking the directories                                                    *
 \****************************************************************************/

#ifndef _PILOCK_H_
#define _PILOCK_H_

#define _POSIX_C_SOURCE  200811L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>

#define LK_SER_SZ 8                      ///< Size of CPU in bytes
#define LK_SIG_SZ 17                     ///< Keychain Signature Size
#define LK_SIG_OFFSET 28                 ///< Keychain Signature Offset
#define LK_MNT_CMD_MAX_SZ 230            ///< Maximum size of fixed chars in cmd
#define LK_CMD_MIN_SZ 91                 ///< Minimux size of fixed chars in cmd
#define LK_TMP_FOLDR "/tmp/codelock/"
#define LK_NO_STDOUT "/dev/null 2>&1"

/**
 * Mount an encrypted path with provided key
 *
 * @param path Absolute path to the destination
 *
 */
uint8_t lk_mount(const char * key, const char* path);

/**
 * Encrypt a directory  with provided key
 *
 * @param path Absolute path to the destination
 * @return int status of the system call to mount
 */
 void lk_encrypt(const char * key, const char * path);

 /**
  * Add a key to keychain and return the fkek
  *
  * @param path Absolute path to the destination
  *
  * @return the signature of the fnek mount.
  */
char * lk_add_keyhcain(const char * key, char output[][LK_SIG_SZ]);

/**
 * Check application user level
 *
 *
 * @return true if application is run as root
 */
bool lk_check_root();

/**
 * Check user input for sane format
 *
 *
 * @return false if input is not acceptable
 */
bool lk_sanitize_input(char * path);

#endif /* _PILOCK_H_ */
