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
 * range of 1 to 0x80. It can suppport larger numbers up to 0x7EFF,           *
 * but smaller numbers create more randomness.                                *
 *                                                                            *
 * Author: Minos Galanakis                                                    *
 * Email: minos197@gmail.com                                                  *
 * License: GPL v3.0                                                          *
 * Project: PiCrypt                                                           *
 * File Description: Main Header File                                         *
 \****************************************************************************/

#ifndef _STRHIDE_H_
#define _STRHIDE_H_
#define _POSIX_C_SOURCE  200811L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <time.h>

/* Allows the following project file to override the salt */
#include "authorized_hwd.h"

#define _STRHT_FIRST_CHAR 0x21                            ///< ! character
#ifndef _STRHT_USR_SALT
#define _STRHT_USR_SALT 0x71                              ///< Obsuscation Salt
#endif  /* Random user salt */
#define _STRHT_ARR_LEN(a, s) ((uint16_t)((s) /sizeof(*(a)))) ///< Data entries

/* Helper macros. DO NOT USE when input arguments are pointers */
#define _STRHT_DECRPT_(e, d) sh_decrypt_string((e),(d),sizeof((e)),sizeof((d)))
#define _STRHT_ENCRPT_(s, e) sh_encrypt_string((s),(e),sizeof((e)))
#define _STRHT_CMP_(a, b) sh_compare_encrypted_str((a),(b),sizeof((a)),sizeof((b)))
#define _STRHT_ARR2HDR_(a, h) sh_array_to_header((a),sizeof((a)),(h))

/**
 * Print byte contents of array
 *
 * @param array array to print.
 * @param byte_size allocated size of array in bytes.
 *
 */
void sh_print_array(int16_t *array, const uint16_t byte_size);

/**
 * Convert the payload of an encrypted buffer to a header file friendly format
 *
 * @param array array to print.
 * @param byte_size allocated size of array in bytes.
 * @param r_buff Buffer to copy the data to.
 *
 * @return A pointer to the output buffer
 */
char * sh_array_to_header(int16_t *array,
                          const uint16_t byte_size,
                          char* r_buff);

/**
 * Ecnryption function that hides a string inside a signed int array
 *
 * @param raw_string Input string.
 * @param output Pre-Allocated buffer to store the result.
 * @param byte_size Size of buffer in bytes.
 *
 */
void sh_encrypt_string(char const *raw_string,
                    int16_t *output,
                    const uint16_t byte_size);

/**
 * Decryption function that converts a signed int array back to original string
 * It will add the null character in the last byte.
 *
 * @param encr_string Input signed integer array.
 * @param output Pre-Allocated buffer to store the result.
 * @param ibuff_byte_size Size of integer (encrypted) buffer in bytes.
 * @param cbuff_byte_size Size of char buffer in bytes.
 *
 * @return The pointer to the char buffer containing the dectypted string
 */
char* sh_decrypt_string(int16_t const *encr_string,
                     char *output,
                     const uint16_t ibuff_byte_size,
                     const uint16_t cbuff_byte_size);

/**
 * Compare two strings in encrypted buffers and return true if the contain the
 * same string. The fucntion assumes the bufffer are of equal length that is
 * defined by the caller.
 *
 * @param en_str_one Input signed integer array.
 * @param en_str_two Pre-Allocated buffer to store the result.
 * @param byte_size Size of buffer in bytes.
 *
 * @return True if strrings are equal False otherwise
 */
bool sh_compare_encrypted_str(int16_t *en_str_one,
                         int16_t *en_str_two,
                         const uint16_t bsize_str_one,
                         const uint16_t bsize_str_two);

/**
* Open a gcc .h header file and replace all occurences of hash defined strings
* with their equivalent encrypted buffer values
*
* @param fname_in Input header file.
* @param fname_out File to be created after the modification.
*
*/
void sh_parse_header(char const *fname_in, char const *fname_out);
#endif /* _STRHIDE_H_ */
