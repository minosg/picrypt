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

/* Print buffer contents in human readable format */
void sh_print_array(int16_t *array, const uint16_t byte_size)
{
  for (uint8_t i=0; i<_STRHT_ARR_LEN(array, byte_size); i++) {
    printf("Byte %d -> 0x%04X\n", i, (uint16_t)array[i]);
  }
}

char * sh_array_to_header(int16_t *array,
                          const uint16_t byte_size,
                          char* r_buff)
{
  uint16_t idx = 1;

  snprintf (r_buff, 2, "{");
  for (uint8_t i=0; i<_STRHT_ARR_LEN(array, byte_size); i++) {
    /* Do not put comma in first entry*/
    if (i==0)  {
      snprintf (r_buff+idx, 7, "0x%04X", (uint16_t)array[i]);
      idx--;
    } else {
      snprintf (r_buff+idx, 8, ",0x%04X", (uint16_t)array[i]);
    }
    idx=idx+7;
  }
  snprintf (r_buff+idx, 2, "}");
  return r_buff;
}

/* Encrypt a string to a Pre-Allocated buffer */
void sh_encrypt_string(char const *raw_string,
                    int16_t *output,
                    const uint16_t byte_size)
{
  int16_t crnt_chr;
  int16_t prev_chr;
  /* Do a small sanity check on the buffers sizes */
  if ((strlen(raw_string) * 2) != byte_size) {
    printf("Warning,  wrongly allocated memory for encrypt buffer:"
           " (str) %zu, (buf) %" PRIu16 "\n",
           strlen(raw_string) * 2 ,
           byte_size);
  }
  /* Limit the number of writes to buffer element count */
  for (uint8_t i=0; i<_STRHT_ARR_LEN(output, byte_size); i++) {
    if (!i) {
      /* Random time based seed */
      srand (time(NULL));

      /* Offset the first character using ! as the starting point of the
      ASCII charset and move it per user salt. */
      crnt_chr = raw_string[i] - _STRHT_FIRST_CHAR;

      /* Store a refference to the last encoded character for distance calc*/
      prev_chr = crnt_chr;
    } else {
      /* Random time and previous element based seed */
      srand (time(NULL)+output[i-1]);

      /* Every consecutive character is cacluated as the ASCII distance to the
      previous taking into consideration offset and salt. */
      crnt_chr = (raw_string[i]- _STRHT_FIRST_CHAR) - prev_chr;

      /* Store a refference to the last encoded character for distance calc*/
      prev_chr = raw_string[i]- _STRHT_FIRST_CHAR;
    }
    /* Store the data using random for bits 0-3 and 12-15 with random data.
     Set bits 4 to 11 with message shifted according to user defined salt */
    output[i] = ((rand() % INT16_MAX) & 0xF00F) |\
                ((crnt_chr + _STRHT_USR_SALT) << 4);
  }
  return;
}

/* Decrypt a string to a Pre-Allocated buffer */
char* sh_decrypt_string(int16_t const *encr_string,
                     char *output,
                     const uint16_t ibuff_byte_size,
                     const uint16_t cbuff_byte_size)
{
  output[0] = 0;
  int16_t c;
  uint8_t len = _STRHT_ARR_LEN(output, cbuff_byte_size);

  /* Do a small sanity check on the buffers sizes */
  if (((cbuff_byte_size - 1) *2) != ibuff_byte_size) {
    printf("Warning,  wrongly allocated memory for decrypt buffer:"
           " (str) %" PRIx16 ", (buf) %" PRIx16 "\n",
           ((cbuff_byte_size - 1) *2) ,
           ibuff_byte_size);
  }
  for (uint8_t i=0; i<len-1; i++) {
    /* Remove the salt and bit shift */
    c = ((encr_string[i] & 0x0FF0) >> 4) -_STRHT_USR_SALT;

    /* When first char remove offset else calculate absolute distance */
    output[i] = c + ((i) ? output[i-1] : _STRHT_FIRST_CHAR);
  }
  output[len-1]=0;
  return output;
}

bool sh_compare_encrypted_str(int16_t *en_str_one,
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

/* Open a header file and encrtypt all string hash defines */
void sh_parse_header(char const *fname_in, char const *fname_out)
{
  char * line = NULL;
  char hashdef[8];
  size_t len = 0;
  size_t read;
  FILE *in_file;
  FILE *out_file;

  // Open the file
  in_file=fopen(fname_in, "r");
  if(in_file==NULL) {
    printf("Error Opening Input File %s!\n", fname_in);
    exit(1);
  }
  remove(fname_out);
  out_file= fopen(fname_out, "a");
  if (out_file == NULL)
  {
      printf("Error Opening Ouptut File %s!\n", fname_out);
      exit(1);
  }
  uint16_t idx = 0;
  uint16_t qte_str = 0;
  uint16_t qte_end = 0;
  while ((read = getline(&line, &len, in_file))!= -1) {

      memset(hashdef, 0, 8);
      qte_str = 0;
      qte_end = 0;

      snprintf (hashdef, 8, "%s", line+idx );
      /* Detect if that is a define line */
      if (!strcmp("#define", hashdef)) {

        /* Iterate through the letters of the define */
        for( uint16_t i = idx+8; i < read-1; i++ ) {
          /* Locate the quote marks*/
          if ( 0x22 == line[i] && (!qte_str)) {
            qte_str = i;
          }
          else if ( 0x22 == line[i] && (qte_str != 0)){
            qte_end = i;
          }
        }

        /* If both quote marks we have a string*/
        if (qte_str && qte_end) {
          /* Get the definition part of the original string */
          char * tmp_str_header = (char*)calloc(qte_str, sizeof(char));
          snprintf (tmp_str_header, qte_str, "%s", line);

          /* Slice the string to extract only chactrers without quotes*/
          uint16_t str_len = qte_end-qte_str;
          char * tmp_str_payload = (char*)calloc(str_len, sizeof(char));
          snprintf (tmp_str_payload, str_len, "%s", line+qte_str+1);

          /* Let user know which entries are modified */
          printf("Encoding %s\n",tmp_str_header);

          /* Encode the payloads */
          int16_t tmp_str_payload_e[str_len-1];
          /* overhead = )(strlength - null) * (char_no*7) ) -1 (, in first c)
          + 2 ({} chars) + 1 null space*/
          uint16_t hdr_str_len = ((str_len - 1) * 7) + 2;
          char tmp_str_payload_d[hdr_str_len];
          _STRHT_ENCRPT_(tmp_str_payload, tmp_str_payload_e);

          /* Print it in header friendly format */
          _STRHT_ARR2HDR_(tmp_str_payload_e, tmp_str_payload_d);

          /* Add an extra character for the newline */
          char line_replace[qte_str+hdr_str_len + 1];
          snprintf (line_replace,
                    qte_str+hdr_str_len +1, "%s %s\n",
                    tmp_str_header,
                    tmp_str_payload_d);

          fprintf(out_file, "%s", line_replace);

          /* Cleanup memory */
          free(tmp_str_header);
          free(tmp_str_payload);
          continue;
        }
      }
      fprintf(out_file, "%s", line);
  }
  fclose(in_file);
  fclose(out_file);
  if (line)
    free(line);
  return;
}
