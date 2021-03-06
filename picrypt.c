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

/* Get the CPU serial and convert it to an integer */
uint64_t pc_pi_serial()
{
  char ser_buffer[CPU_SER_SIZE+1];
  pc_string_slice_from_file(CPU_FILE, CPU_SER_OFFSET, CPU_SER_SIZE, ser_buffer);
  return (uint64_t)strtoull(ser_buffer, NULL, 16);
}

/* Open a file and read a substring into a buffer */
void pc_string_slice_from_file(char const *fname,
                            const uint32_t offset,
                            const uint32_t byte_size,
                            char *buffer)
{
  FILE *fptr;
  // Open the file
  fptr=fopen(fname, "r");
  if(fptr==NULL) {
    #ifdef DEVEL
    printf("Error Opening File %s\n", fname);
    #endif
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
void pc_soft_machine_id(char *ret_buff)
{
  pc_string_slice_from_file(MACHINE_ID_FILE, 0, MACHINE_ID_SIZE, ret_buff);
  return;
}
#if defined(FILE_SEED) && defined(FILE_SHA1)

/* Calcualte SHA1 from a valid file path */
char * pc_sha1_from_file(char * fname, char *sha_hash)
{
  FILE *fptr;
  unsigned char sha1_buffer[SHA_DIGEST_LENGTH];
  unsigned char *fbuffer;
  unsigned long fileLen;

  // Open the file
  fptr=fopen(fname, "rb");
  if (!fptr) {
    #ifdef DEVEL
    fprintf(stderr, "Unable to open file %s\n", fname );
    #endif
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
/* Calculate SHA1 from a file path that is encryted using strhide */
char * pc_sha1_from_en_buf(int16_t const *fname,
                        const uint16_t byte_size,
                        char *sha_hash)
{
  /* Get the file path */
  char fname_d[strlen(FILE_SEED)+1];
  sh_decrypt_string(fname, fname_d, byte_size, sizeof(fname_d));
  return pc_sha1_from_file(fname_d, sha_hash);
}

/* Calculate SHA1 from a file path that is encryted using strhide and return
it using the same encryption */
int16_t * pc_sha1_from_en_buf_to_en_buff(int16_t const *fname,
                                     const uint16_t byte_size,
                                     int16_t *sha_buff)
{
  /* Calcuate the sha1 */
  char sha_d[(SHA_DIGEST_LENGTH*2)+1];

  /* If File does not exist exit */
  if (pc_sha1_from_en_buf(fname,byte_size, sha_d) == NULL){
    return NULL;
  }

  /* During encryption one char is encoded as 4 bytes */
  sh_encrypt_string(sha_d, sha_buff, SHA_DIGEST_LENGTH*4);
  return sha_buff;
}
#endif

/* Return the hash in printable string format (Do not edit) */
char * pc_hash_str(hw_msg_page_t * hwinfo, char * hash_buffer)
{
  char LB[9];
  hash_low(hwinfo, LB);
  #ifdef LONG_HASH
  char HB[9];
  hash_high(hwinfo, HB);
  snprintf(hash_buffer, HBUFF_SZ+1, "%s%s", HB, LB);
  #else
  snprintf(hash_buffer, HBUFF_SZ+1, "%s", LB);
  #endif
  return hash_buffer;
}

/* Return the hash in printable string format (Do not edit) */
int16_t * pc_hash_enc(hw_msg_page_t * hwinfo,
                   int16_t * hash_buffer_e,
                   const uint16_t byte_size)
{
  char tmp_hash_bf[HBUFF_SZ+1];
  pc_hash_str(hwinfo, tmp_hash_bf);
  sh_encrypt_string(tmp_hash_bf, hash_buffer_e, byte_size);
  return hash_buffer_e;
}

/* verify that a key is valid for this hardware */
bool pc_validate_key(char const *key)
{
  char hash_key_d[(strlen(key) * 2) + 1];
  if (strlen(key) > 8) {
    return false;
  }

  /* Create a temporary hardware_info structure and add the serial */
  uint64_t ukey = (uint64_t)strtoull(key, NULL, 16);
  hw_msg_page_t * tmp_data = hw_msg_init();
  hw_msg_add(tmp_data, HW_SERIAL, &ukey);
  /* Assume it is authorized, or it will fail user anti-tamper */
  bool authorized = true;
  hw_msg_add(tmp_data, HW_AUTHORIZED, (bool *)(&authorized));

  /* Calculate the hash */
  pc_hash_str(tmp_data, hash_key_d);

  /* Free the memory */
  hw_free(tmp_data);

  /* Compare the strings and square to get rid of the negatives */
  int16_t r = strcmp(hash_key_d, key);
  return !(bool)(r*r);
}

/* Diplay a pc_help menu */
void pc_help(const char* prgm)
{
  printf("<---------------------- Options -------------------------------->\n");
  #ifdef DEVEL
  printf("%s --hash          : Generate Unique Machine Hash\n", prgm);
  printf("%s --check xxxxxx  : Check if a key is valid or not \n", prgm);
  printf("%s --vhash         : Print Verbose Unique Machine Hash\n", prgm);
  #endif
  printf("%s --mount /absolute_path  : Mount an encrypted path \n", prgm);
  printf("%s --encrypt /absolute_path : Encrypt a path using hwd keys\n", prgm);
}
