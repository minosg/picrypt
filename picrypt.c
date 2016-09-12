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
 * File Description: Method Implementations                                   *
 \****************************************************************************/

#include "authorized_hwd.h"
#include "picrypt.h"
#include <openssl/sha.h>

/**************************\
* Custom User Lock         *
\**************************/

/* Change the method of calculating the key to YOUR OWN CUSTOM and UNIQUE
method. By defualy it just generates a key equal to the cpu serial, which is
UNSAFE. Esure you maintain the cast to 64Bit unsigned integer before returning
the result of your method */

uint64_t hash(const uint64_t serial)
{
  return (uint64_t)(serial);
}

/**************************\
* Method Implementations   *
\**************************/
char * sha1_from_file(char * fname, char *sha_hash)
{
  FILE *fptr;
  unsigned char sha1_buffer[SHA_DIGEST_LENGTH];
  unsigned char *fbuffer;
  unsigned long fileLen;

  // Open the file
  fptr=fopen("/etc/fstab", "rb");
  if (!fptr)
  {
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
  for(int i = 0;i < SHA_DIGEST_LENGTH;++i){
    snprintf(sha_hash+j, 4 ,"%02x", sha1_buffer[i]);
    j += 2;
  }
  /* No null termination required, snprintf will add it */
  free(fbuffer);
  return sha_hash;
}

char * sha1_from_en_buf(int16_t const *fname,const uint16_t byte_size, char *sha_hash)
{
  /* Get the file path */
  char fname_d[strlen(FILE_SEED)+1];
  decrypt_string(fname, fname_d, sizeof(fname_d));
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

void string_slice_from_file(char const *fname,
                            const uint32_t offset,
                            const uint32_t byte_size,
                            char *buffer)
{
        FILE *fptr;
        // Open the file
        fptr=fopen(fname, "r");
        if(fptr==NULL) {
                printf("Error!");
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

uint64_t pi_serial()
{

        char ser_buffer[CPU_SER_SIZE+1];
        string_slice_from_file(CPU_FILE, CPU_SER_OFFSET, CPU_SER_SIZE, ser_buffer);
        return (uint64_t)strtoull(ser_buffer, NULL, 16);
}

void soft_machine_id(char *ret_buff)
{
        string_slice_from_file(MACHINE_ID_FILE, 0, MACHINE_ID_SIZE, ret_buff);
        return;
}

void ram_key(const uint64_t hash_key)
{
        FILE *fptr;
        fptr=fopen(RAM_FILE,"w");
        if(fptr==NULL) {
                printf("Error!");
                exit(1);
        }

        char key_text[28];
        sprintf(key_text, "passphrase_passwd=%" PRIx64 "", hash_key);
        fprintf(fptr,"%s\n",key_text);
        fclose(fptr);
}

bool validate_key(char const *key)
{
        if (strlen(key) > 8)
        {
                return false;
        }
        uint64_t ukey = (uint64_t)strtoull(key, NULL, 16);
        uint64_t hdw_key = hash(pi_serial());

        if (ukey == hdw_key) {
                return true;
        } else {
                return false;
        }
}

void help(const char* prgm)
{
        printf("<---------------------- Options -------------------------------->\n");
        printf("%s --hash          : Generate Unique Machine Hash\n", prgm);
        printf("%s --vhash         : Print Verbose Unique Machine Hash\n", prgm);
        printf("%s --ramkey        : Create an encryptfs unlock key to RAM \n", prgm);
        printf("%s --check xxxxxx  : Check if a key is valid or not \n", prgm);
}

/********************
   Main Code
 *********************/

int main(int argc, char **argv)
{
        bool permitted = true;
        #ifdef HWD_ID
          uint64_t serial = pi_serial();
          uint64_t hash_key = hash(serial);
          uint64_t permitted_serial = (uint64_t)strtoull(HWD_ID, NULL, 16);
          if ((PROTECTION >= SCRIPT_KIDDY) && (permitted_serial != serial))
          {
            printf("Serial Miss-Match!! \n");
            permitted = false;
          }
        #endif
        #ifdef MACHINE_ID
          /* Allocate buffers */
          int16_t machine_id_hd_e[MACHINE_ID_SIZE * 2];
          int16_t machine_id_rt_e[MACHINE_ID_SIZE * 2];

          /* Exctact Current Machine ID (not sensitive) */
          char machine_id_hd_d[MACHINE_ID_SIZE + 1];
          soft_machine_id(machine_id_hd_d);

          encrypt_string(MACHINE_ID, machine_id_hd_e, sizeof(machine_id_hd_e));
          encrypt_string(machine_id_hd_d, machine_id_rt_e, sizeof(machine_id_rt_e));

          if (PROTECTION >= ARCH_USER)
          {
            if (!compare_encrypted_str(machine_id_rt_e,
                              machine_id_hd_e,
                              sizeof(machine_id_rt_e),
                              sizeof(machine_id_hd_e)))
            {
              printf("Machine ID Miss Match!! \n");
              permitted = false;
            }
          }
        #endif

        #if defined(FILE_SEED) && defined(FILE_SHA1)
          /* Allocate the buffers that will hide the filename and seed */
          /* Naming convention:
           variable_hd/rt_e -> variable name,
                               hash_defined/runtime
                               encrypted/decrypted*/
          int16_t file_seed_hd_e[strlen(FILE_SEED)];
          int16_t file_sha_hd_e[SHA_DIGEST_LENGTH * 2];
          int16_t file_sha_rt_e[SHA_DIGEST_LENGTH * 2];

          /* Allocate the memory for the decryption buffers */
          char file_sha_rt_d[(SHA_DIGEST_LENGTH * 2) + 1];
          char sha_hash_rt_d[(SHA_DIGEST_LENGTH * 2) + 1];

          /* Store the sensitive information */
          encrypt_string(FILE_SEED, file_seed_hd_e, sizeof(file_seed_hd_e));
          encrypt_string(FILE_SHA1, file_sha_hd_e, sizeof(file_sha_hd_e));
          sha1_from_en_buf_to_en_buff(file_seed_hd_e, sizeof(file_seed_hd_e), file_sha_rt_e);

          printf("Defined SHA: %s\n", decrypt_string(file_sha_hd_e, file_sha_rt_d, sizeof(file_sha_rt_d)) );
          printf("Runtime SHA: %s\n", decrypt_string(file_sha_rt_e, sha_hash_rt_d, sizeof(sha_hash_rt_d)));

          if (PROTECTION >= PEN_TESTER)
          {
            if (!compare_encrypted_str(file_sha_rt_e,
                            file_sha_hd_e,
                            sizeof(file_sha_rt_e),
                            sizeof(file_sha_hd_e)))
            {
              printf("SHA1 Miss-Match!! \n");
              permitted = false;
            }
          }


        #endif
        /* Ensure the executable is run from intended machine.
           This check is important because the executable is not encrypted,
           and running it over to a different hwd would be an attack vector. */

        if (!permitted)
        {
          printf("This is the password you are looking for...\n"
                 "( You pesky pirate !!! )\n");
          exit(1);
        }

        if (argc == 1) {
                help(argv[0]);
        } else if (argc == 2 && !strcmp(argv[1],"--ramkey")) {
                ram_key(hash(serial));
                printf("%" PRIx64 "\n", hash_key);
        } else if (argc == 2 && !strcmp(argv[1],"--vhash")) {
                printf("Calculating Hash\n");
                printf("Serial (int): %" PRIu64 "\nSerial (hex): %" PRIx64 " \n", serial, serial);
                printf("Machine-id:   %s\n",machine_id_hd_d);
                printf("Hash Key:     %" PRIx64 "\n", hash_key);
        } else if (argc == 2 && !strcmp(argv[1],"--hash")) {
                printf("%" PRIx64 "\n", hash_key);
        } else if (argc == 3 && !strcmp(argv[1],"--check")) {
                if (validate_key(argv[2])) {
                        printf("Key %s is Valid\n", argv[2]);
                        return 0;
                } else {
                        printf("Key %s is Invalid\n", argv[2]);
                        return 1;
                }
        } else {
                help(argv[0]);
        }
        return 0;
}
