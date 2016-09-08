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


#include "picrypt.h"
#include "authorized_hwd.h"

/**************************\
* Custom User Lock         *
\**************************/

/* Change the method of calculating the key to YOUR OWN CUSTOM and UNIQUE
method. By defualy it just generates a key equal to the cpu serial, which is
UNSAFE. Esure you maintain the cast to 64Bit unsigned integer before returning
the result of your method */

uint64_t hash(uint64_t serial)
{
  return (uint64_t)(serial);
}

/**************************\
* Method Implementations   *
\**************************/

void string_slice_from_file(char * fname,
                            uint32_t offset,
                            uint32_t byte_size,
                            char (*buffer)[])
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
        fgets(*buffer, byte_size+1, fptr);
        fclose(fptr);
        return;
}

uint64_t pi_serial()
{

        char ser_buffer[CPU_SER_SIZE+1];
        string_slice_from_file(CPU_FILE, CPU_SER_OFFSET, CPU_SER_SIZE, &ser_buffer);
        return (uint64_t)strtoull(ser_buffer, NULL, 16);
}

void soft_machine_id(char (*ret_buff)[])
{
        string_slice_from_file(MACHINE_ID_FILE, 0, MACHINE_ID_SIZE, ret_buff);
        return;
}

void ram_key(uint64_t hash_key)
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

bool validate_key(char* key)
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

        char m_id[MACHINE_ID_SIZE+1];
        soft_machine_id(&m_id);

        uint64_t serial = pi_serial();
        uint64_t hash_key = hash(serial);

        /* Ensure the executable is run from intended machine.
           This check is important because the executable is not encrypted,
           and running it over to a different hwd would be an attack vector. */
        uint64_t permitted_serial = (uint64_t)strtoull(HWD_ID, NULL, 16);

        #if GODMODE != 1
        if (permitted_serial != serial || strcmp(MACHINE_ID,m_id) != 0) {
                printf("@@ is the password you seek, you pesky pirate!!!\n");
                exit(1);
        }
        #endif

        if (argc == 1) {
                help(argv[0]);
        } else if (argc == 2 && !strcmp(argv[1],"--ramkey")) {
                ram_key(hash(serial));
                printf("%" PRIx64 "\n", hash_key);
        } else if (argc == 2 && !strcmp(argv[1],"--vhash")) {
                printf("Calculating Hash\n");
                printf("Serial (int): %" PRIu64 "\nSerial (hex): %" PRIx64 " \n", serial, serial);
                printf("Machine-id:   %s\n",m_id);
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
