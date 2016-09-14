/*****************************************************************************\
 * PiCrypt is a software key generator for ecryptfs locked system.             *
 * Since the program is meant to unlock the protected area, it has to be      *
 * decrypted itself but will perform a set of  hardware tests before producing*
 * the unlock key.                                                            *
 *                                                                            *
 * Author: Minos Galanakis                                                    *
 * Email: minos197@gmail.com                                                  *
 * License: GPL v3.0                                                          *
 * Project: PiCrypt                                                           *
 * File Description: Main Program                                             *
 \****************************************************************************/

#include "authorized_hwd.h"
#include "picrypt.h"

int main(int argc, char **argv)
{
  bool permitted = true;
  hwd_nfo_param_t * hardware_info = hwinfo_init();
  uint64_t hash_key =0 ;
  #ifdef HWD_ID
  uint64_t serial = pi_serial();
  //uint64_t serial =1421114121;
  uint64_t permitted_serial = (uint64_t)strtoull(HWD_ID, NULL, 16);

  /* Add the data to the hw_info structure */
  hwinfo_add(hardware_info, HW_SERIAL, &serial);

  if ((PROTECTION >= SCRIPT_KIDDY) && (permitted_serial != serial)) {
    printf("Serial Miss-Match!! \n");
    permitted = false;
  }

  #endif
  #ifdef MACHINE_ID
  /* Allocate buffers */
  int16_t machine_id_hd_e[MACHINE_ID_SIZE];
  int16_t machine_id_rt_e[MACHINE_ID_SIZE];

  /* Exctact Current Machine ID (not sensitive) */
  char machine_id_hd_d[MACHINE_ID_SIZE + 1];
  soft_machine_id(machine_id_hd_d);

  /* Add the machine-id to the hw_info structure */
  hwinfo_add(hardware_info, HW_MACHINE_ID, machine_id_hd_d);

  encrypt_string(MACHINE_ID, machine_id_hd_e, sizeof(machine_id_hd_e));
  encrypt_string(machine_id_hd_d, machine_id_rt_e, sizeof(machine_id_rt_e));

  if (PROTECTION >= ARCH_USER) {
    if (!compare_encrypted_str(machine_id_rt_e,
                               machine_id_hd_e,
                               sizeof(machine_id_rt_e),
                               sizeof(machine_id_hd_e))) {
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
  // char file_sha_rt_d[(SHA_DIGEST_LENGTH * 2) + 1]; /* Placeholder */
  char sha_hash_rt_d[(SHA_DIGEST_LENGTH * 2) + 1];
  char file_seed_hd_d[strlen(FILE_SEED)+1];

  /* Store the sensitive information */
  encrypt_string(FILE_SEED, file_seed_hd_e, sizeof(file_seed_hd_e));
  encrypt_string(FILE_SHA1, file_sha_hd_e, sizeof(file_sha_hd_e));
  sha1_from_en_buf_to_en_buff(file_seed_hd_e,
                              sizeof(file_seed_hd_e),
                              file_sha_rt_e);

  /* Add the sha1 to the hw_info structure */
  decrypt_string(file_sha_rt_e,
                 sha_hash_rt_d,
                 sizeof(file_sha_rt_e),
                 sizeof(sha_hash_rt_d));
  hwinfo_add(hardware_info, HW_SHA1, sha_hash_rt_d);

  if (PROTECTION >= PEN_TESTER) {
    if (!compare_encrypted_str(file_sha_rt_e,
                               file_sha_hd_e,
                               sizeof(file_sha_rt_e),
                               sizeof(file_sha_hd_e))) {
      printf("SHA1 Miss-Match!! \n");
      permitted = false;
    }
  }
  #endif

  /* Ensure the executable is run from intended machine.
     This check is important because the executable is not encrypted,
     and running it over to a different hwd would be an attack vector. */
  if (!permitted) {
    printf("This is the password you are looking for...\n"
           "( You pesky pirate !!! )\n");
    exit(1);
  } else {
    hash_key = hash_low(hardware_info);
  }

  if (argc == 1) {
    help(argv[0]);
  #ifdef HWD_ID
  } else if (argc == 2 && !strcmp(argv[1],"--ramkey")) {
    ram_key(hash_key);
    printf("%" PRIx64 "\n", hash_key);
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
  #endif
  } else if (argc == 2 && !strcmp(argv[1],"--vhash")) {
    printf("\n[ Runtime Hardware Keys ] \n");
    #ifdef HWD_ID
    printf("Serial (int): %" PRIu64 "\nSerial (hex): %" PRIx64 " \n",
           serial,
           serial);
    printf("Hash Key:     %" PRIx64 "\n", hash_key);
    #endif
    #ifdef MACHINE_ID
    printf("Machine-id:   %s\n",(char *)hwinfo_get_pl(hardware_info,
                                                      HW_MACHINE_ID));
    #endif
    #if defined(FILE_SEED) && defined(FILE_SHA1)
    printf("KeyFile:      %s\n",
            decrypt_string(file_seed_hd_e,
                           file_seed_hd_d,
                           sizeof(file_seed_hd_e),
                           sizeof(file_seed_hd_d)));
    printf("SHA1 Key:     %s\n", (char *)hwinfo_get_pl(hardware_info,HW_SHA1));

    #endif
  } else {
    help(argv[0]);
  }
  return 0;
}
