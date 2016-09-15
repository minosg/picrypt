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
 * File Description: Method Implementations                                   *
 \****************************************************************************/

#include "authorized_hwd.h"
#include "picrypt.h"

/**************************\
* Method Implementations   *
\**************************/

uint64_t pi_serial()
{
  char ser_buffer[CPU_SER_SIZE+1];
  string_slice_from_file(CPU_FILE, CPU_SER_OFFSET, CPU_SER_SIZE, ser_buffer);
  return (uint64_t)strtoull(ser_buffer, NULL, 16);
}

void string_slice_from_file(char const *fname,
                            const uint32_t offset,
                            const uint32_t byte_size,
                            char *buffer)
{
  FILE *fptr;
  // Open the file
  fptr=fopen(fname, "r");
  if(fptr==NULL) {
    printf("Error Opening File!");
    exit(1);
  }
  if (offset) {
    // Go to offset where the serial number is stored
    fseek(fptr, offset, SEEK_SET);
  }
  /* Read the data from the file into the string */
  fgets(buffer, byte_size+1, fptr);
  fclose(fptr);
  return;
}

/* Copy the software machine id string from file to an initialized buffer */
void soft_machine_id(char *ret_buff)
{
  string_slice_from_file(MACHINE_ID_FILE, 0, MACHINE_ID_SIZE, ret_buff);
  return;
}

char * sha1_from_file(char * fname, char *sha_hash)
{
  FILE *fptr;
  unsigned char sha1_buffer[SHA_DIGEST_LENGTH];
  unsigned char *fbuffer;
  unsigned long fileLen;

  // Open the file
  fptr=fopen("/etc/fstab", "rb");
  if (!fptr) {
    fprintf(stderr, "Unable to open file %s", "name");
    return NULL;
  }

  //Get file length
  fseek(fptr, 0, SEEK_END);
  fileLen=ftell(fptr);
  fseek(fptr, 0, SEEK_SET);

  //Allocate memory
  fbuffer=(unsigned char *)malloc(fileLen+1);

  //Read file contents into buffer
  fread(fbuffer, fileLen, 1, fptr);
  fclose(fptr);

  /* Calculate SHA1 Hash */
  SHA1(fbuffer, fileLen, sha1_buffer);

  uint8_t j=0;
  /* Go through the buffer, convert the chars to zero-padded hex strings */
  for(int i = 0;i < SHA_DIGEST_LENGTH;++i) {
    snprintf(sha_hash+j, 4 ,"%02x", sha1_buffer[i]);
    j += 2;
  }
  /* No null termination required, snprintf will add it */
  free(fbuffer);
  return sha_hash;
}

#if defined(FILE_SEED) && defined(FILE_SHA1)
char * sha1_from_en_buf(int16_t const *fname,const uint16_t byte_size, char *sha_hash)
{
  /* Get the file path */
  char fname_d[strlen(FILE_SEED)+1];
  decrypt_string(fname, fname_d, byte_size, sizeof(fname_d));
  return sha1_from_file(fname_d, sha_hash);
}

int16_t * sha1_from_en_buf_to_en_buff(int16_t const *fname,
                                     const uint16_t byte_size,
                                     int16_t *sha_buff)
{
  /* Calcuate the sha1 */
  char sha_d[(SHA_DIGEST_LENGTH*2)+1];
  sha1_from_en_buf(fname,byte_size, sha_d);

  /* During encryption one char is encoded as 4 bytes */
  encrypt_string(sha_d, sha_buff, SHA_DIGEST_LENGTH*4);
  return sha_buff;
}
#endif

/* Return the hash in printable string format (Do not edit) */
char * hash_str(hwd_nfo_param_t * hwinfo, char * hash_buffer)
{
  uint64_t LB = hash_low(hwinfo);
  #ifdef LONG_HASH
  uint64_t HB = hash_high(hwinfo);
  snprintf(hash_buffer, HBUFF_SZ+1, "%08" PRIx64 "%08" PRIx64 "", HB, LB);
  #else
  snprintf(hash_buffer, HBUFF_SZ+1, "%08" PRIx64 "", LB);
  #endif
  return hash_buffer;
}

/* Return the hash in printable string format (Do not edit) */
int16_t * hash_enc(hwd_nfo_param_t * hwinfo, int16_t * hash_buffer_e, const uint16_t byte_size)
{
  char tmp_hash_bf[HBUFF_SZ+1];
  hash_str(hwinfo, tmp_hash_bf);
  encrypt_string(tmp_hash_bf, hash_buffer_e, byte_size);
  return hash_buffer_e;
}

void ram_key(const char * hash_key)
{
  FILE *fptr;
  fptr=fopen(RAM_FILE,"w");
  if(fptr==NULL) {
    printf("Error!");
    exit(1);
  }

  char key_text[36];
  sprintf(key_text, "passphrase_passwd=%s", hash_key);
  fprintf(fptr,"%s\n",key_text);
  fclose(fptr);
}

bool validate_key(char const *key)
{
  if (strlen(key) > 8) {
    return false;
  }
  uint64_t ukey = (uint64_t)strtoull(key, NULL, 16);
  /* Create a temporary hardware_info structure and add the serial */
  hwd_nfo_param_t * tmp_data = hwinfo_init();
  hwinfo_add(tmp_data, HW_SERIAL, &ukey);

  uint64_t hdw_key = hash_low(tmp_data);
  /* Free the memory */
  hwinfo_dealloc(tmp_data);

  if (ukey == hdw_key) {
    return true;
  } else {
    return false;
  }
}



void help(const char* prgm)
{
  printf("<---------------------- Options -------------------------------->\n");
  #ifdef HWD_ID
  printf("%s --hash          : Generate Unique Machine Hash\n", prgm);
  printf("%s --ramkey        : Create an encryptfs unlock key to RAM \n", prgm);
  printf("%s --check xxxxxx  : Check if a key is valid or not \n", prgm);
  #endif
  printf("%s --vhash         : Print Verbose Unique Machine Hash\n", prgm);
}
