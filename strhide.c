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
 * range of 1 to 32511 or 0x7EFF.                                             *
 *                                                                            *
 * Author: Minos Galanakis                                                    *
 * Email: minos197@gmail.com                                                  *
 * License: GPL v3.0                                                          *
 * Project: PiCrypt                                                           *
 * File Description: Method Implementation                                    *
 \****************************************************************************/

#include "strhide.h"

void print_array(int16_t *array, uint8_t byte_size)
{
  for (uint8_t i=0; i<_STRHT_ARR_LEN(array, byte_size); i++) {
    printf("Byte %d -> %x\n", i, array[i]);
  }
}

void random_fill_array(int16_t *array, uint8_t byte_size)
{
  for (uint8_t i=0; i<_STRHT_ARR_LEN(array, byte_size); i++) {
    /* Seed random with time and previous element if exists */
    if (!i) srand (time(NULL));
    else srand (time(NULL)+array[i-1]);
    /* Empty centre bits for the obsuscated integer */
    array[i] = (rand() % INT16_MAX) & 0xF00F;
  }
}

void encrypt_fname(char *raw_string, int16_t *output, uint8_t byte_size)
{
  char c;
  for (uint8_t i=0; i<_STRHT_ARR_LEN(output, byte_size); i++) {
     /* Offset the first character using ! as the starting point of the
     ASCII charset and move it per user salt. */
    if (!i)  c = raw_string[i] - _STRHT_FIRST_CHAR;
    /* Every consecutive character is cacluated as the distance to the previous
    taking into consideration offset and sal. */
    else c = (raw_string[i]- _STRHT_FIRST_CHAR) - raw_string[i-1];
    /* Set the bits 4 to 13 only , including the user salt*/
    output[i] = (output[i] & 0xF00F) | (c + _STRHT_USR_SALT) << 4;
  }
  return;
}

char* decrypt_fname(int16_t *encr_string, char *output, uint8_t byte_size)
{
  output[0] = 0;
  char c;
  uint8_t len = _STRHT_ARR_LEN(output, byte_size);
  for (uint8_t i=0; i<len-1; i++) {
    /* First character is directly decoded by masking the junk
    bytes and bit shifting */
    if (!i)  c = (encr_string[i] & 0x0FF0) >> 4;
    /* Consecutive characters are decoded in respect to previous character */
    else c =  ((encr_string[i] & 0x0FF0) >> 4) + output[i-1];

    /* Finally remove user salt and offset */
    output[i] = c + _STRHT_FIRST_CHAR -_STRHT_USR_SALT;
  }
  output[len-1]=0;
  return output;
}
