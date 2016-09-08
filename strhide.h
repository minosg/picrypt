/*****************************************************************************\
 * Strhide serves the purpose of hiding sensitive strings in binary code. It  *
 * aims to do so by offseting the typeable ASCII Characters to the first      *
 * acceptable for a filename (!) , and then hide it between random noise in a *
 * 4 Bytes usigned integer, which is bit shifted and bit masked. A string is  *
 * stored as a breadcrumb trail, that each character is represented as the    *
 * distance to previous character.                                            *
 *                                                                            *
 * In order to protect from attach vectors on common characters ie "/" used   *
 * in file paths, a USER Input salt is defined to ensure the uniqueness of    *
 * the represention. It is advised to change is and choose any number in the  *
 * range of 1 to 32511 or 0x7EFF, but smaller numbers create more randomness. *
 *                                                                            *
 * Author: Minos Galanakis                                                    *
 * Email: minos197@gmail.com                                                  *
 * License: GPL v3.0                                                          *
 * Project: PiCrypt                                                           *
 * File Description: Main Header File                                         *
 \****************************************************************************/

#ifndef _STRHIDE_H_
#define _STRHIDE_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <time.h>

#define _STRHT_FIRST_CHAR 0x21                            ///< ! character
#ifndef _STRHT_USR_SALT
#define _STRHT_USR_SALT 0x71                              ///< Obsuscation Salt
#endif  /* Random user salt */
#define _STRHT_ARR_LEN(a, s) ((uint8_t)(s) /sizeof(*(a))) ///< Data len for arr

#endif /* _STRHIDE_H_ */

/**
 * Print byte contents of array
 *
 * @param serial array array to print.
 * @param serial byte_size allocated size of array in bytes.
 *
 */
void print_array(int16_t *array, uint8_t byte_size);

/**
 * Fill int16_t array elements with random data byte masked by 0xF00F
 *
 * @param serial array array to fill.
 * @param serial byte_size allocated size of array in bytes.
 *
 */
void random_fill_array(int16_t *array, uint8_t byte_size);

/**
 * Ecnryption function that hides a string inside a signed int array
 *
 * @param raw_string Input string.
 * @param output Pre-Allocated buffer to store the result.
 * @param byte_size Size of buffer in bytes.
 *
 */
void encrypt_fname(char *raw_string, int16_t *output, uint8_t byte_size);

/**
 * Decryption function that converts a signed int array back to original string
 * It will add the null character in the last byte.
 *
 * @param encr_string Input signed integer array.
 * @param output Pre-Allocated buffer to store the result.
 * @param byte_size Size of buffer in bytes.
 *
 */
char* decrypt_fname(int16_t *encr_string, char *output, uint8_t byte_size);
