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

void print_array(int16_t *array, const uint16_t byte_size)
{
  for (uint8_t i=0; i<_STRHT_ARR_LEN(array, byte_size); i++) {
    printf("Byte %d -> 0x%04X\n", i, array[i]);
  }
}

void encrypt_string(char const *raw_string,
                    int16_t *output,
                    const uint16_t byte_size)
{
  char c;
  /* Do a small sanity check on the buffers sizes */
  if ((strlen(raw_string) * 2) != byte_size) {
    printf("Warning,  wrongly allocated memory for encrypt buffer:"
           " (str) %ld, (buf) %" PRIx16 "\n",
           strlen(raw_string) * 2 ,
           byte_size);
  }
  /* Limit the number of writes to buffer element count */
  for (uint8_t i=0; i<_STRHT_ARR_LEN(output, byte_size); i++) {
    if (!i)
    {
      /* Random time based seed */
      srand (time(NULL));
      /* Offset the first character using ! as the starting point of the
      ASCII charset and move it per user salt. */
      c = raw_string[i] - _STRHT_FIRST_CHAR;
    }
    else
    {
      /* Random time and previous element based seed */
      srand (time(NULL)+output[i-1]);

      /* Every consecutive character is cacluated as the distance to the
      previous taking into consideration offset and salt. */
      c = (raw_string[i]- _STRHT_FIRST_CHAR) - raw_string[i-1];
    }
    /* Store the data using random for bits 0-3 and 12-15 with random data.
     Set bits 4 to 11 with message shifted according to user defined salt */
    output[i] = ((rand() % INT16_MAX) & 0xF00F) | (c + _STRHT_USR_SALT) << 4;
  }
  return;
}

char* decrypt_string(int16_t const *encr_string,
                     char *output,
                     const uint16_t ibuff_byte_size,
                     const uint16_t cbuff_byte_size)
{
  output[0] = 0;
  char c;
  uint8_t len = _STRHT_ARR_LEN(output, cbuff_byte_size);

  /* Do a small sanity check on the buffers sizes */
  if (((cbuff_byte_size - 1) *2) != ibuff_byte_size) {
    printf("Warning,  wrongly allocated memory for decrypt buffer:"
           " (str) %" PRIx16 ", (buf) %" PRIx16 "\n",
           ((cbuff_byte_size - 1) *2) ,
           ibuff_byte_size);
  }
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

bool compare_encrypted_str(int16_t *en_str_one,
                          int16_t *en_str_two,
                          const uint16_t bsize_str_one,
                          const uint16_t bsize_str_two)
{
  bool ret = true;

  /* If buffers of different size, return not equal */
  if (bsize_str_one != bsize_str_two) return false;

  /* Go through the buffer and compare the masked contents. If a single char
  does not match the strings are not equal */
  for (uint8_t i=0; i<_STRHT_ARR_LEN(en_str_one, bsize_str_one); i++) {
    if ((en_str_one[i] & 0x0FF0) != (en_str_two[i] & 0x0FF0)) ret = false;
  }
  return ret;
}
