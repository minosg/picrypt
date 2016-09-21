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

#include "authorized_hwd_e.h"
#include "picrypt.h"

int main(int argc, char **argv)
{
  bool permitted = true;
  hwd_nfo_param_t * hardware_info = hwinfo_init();
  char hash_key_d[HBUFF_SZ+1];
  int16_t hash_key_e[HBUFF_SZ];

  /* Add breakpoint detection to critical methods */
 uint8_t btd = (bp_det((RAM_ADDR_SZ)&hwinfo_add)+\
                 bp_det((RAM_ADDR_SZ)&soft_machine_id)+\
                 bp_det((RAM_ADDR_SZ)&sha1_from_en_buf_to_en_buff)+\
                 bp_det((RAM_ADDR_SZ)&hash_enc)+\
                 bp_det((RAM_ADDR_SZ)&hwinfo_add)+\
                 bp_det((RAM_ADDR_SZ)&encrypt_string)+\
                 bp_det((RAM_ADDR_SZ)&hwinfo_get_pl));
  if (btd != 0) {
    printf("Warning Tampering Detected (bp)\n");
    permitted = false;
    // TODO Make it goto somewhere
  }

  #ifdef HWD_ID
  /* Allow the user to override the detected CPU serial */
  #ifndef FAKE_SERIAL
  uint64_t serial = pi_serial();
  #else
  uint64_t serial = (uint64_t)FAKE_SERIAL;
  #endif

  /* Decrypt the Authorized CPU Serial */
  const int16_t hardware_id_e[] = HWD_ID;
  char hardware_id_d[CPU_SER_SIZE + 1];
  _STRHT_DECRPT_(hardware_id_e, hardware_id_d);
  uint64_t permitted_serial = (uint64_t)strtoull(hardware_id_d, NULL, 16);

  /* Add the data to the hw_info structure */
  hwinfo_add(hardware_info, HW_SERIAL, &serial);

  if ((PROTECTION >= SCRIPT_KIDDY) && (permitted_serial != serial)) {
    #ifdef DEVEL
    printf("Serial Miss-Match!! \n");
    #endif
    permitted = false;
  }
  #endif
  #ifdef MACHINE_ID
  /* Allocate buffers */
  int16_t machine_id_hd_e[] = MACHINE_ID;
  int16_t machine_id_rt_e[MACHINE_ID_SIZE];

  /* Decryption Buffer */
  // char machine_id_hd_d[MACHINE_ID_SIZE + 1]; /* Placeholder */

  /* Exctact Current Machine ID (not sensitive) */
  char machine_id_rt_d[MACHINE_ID_SIZE + 1];
  soft_machine_id(machine_id_rt_d);

  /* Add the machine-id to the hw_info structure */
  hwinfo_add(hardware_info, HW_MACHINE_ID, machine_id_rt_d);

  _STRHT_ENCRPT_(machine_id_rt_d, machine_id_rt_e);

  if (PROTECTION >= ARCH_USER) {
    if (!_STRHT_CMP_(machine_id_rt_e, machine_id_hd_e)) {
      #ifdef DEVEL
      printf("Machine ID Miss Match!! \n");
      #endif
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
  int16_t file_seed_hd_e[] = FILE_SEED;
  int16_t file_sha_hd_e[] = FILE_SHA1;
  int16_t file_sha_rt_e[SHA_DIGEST_LENGTH * 2];

  /* Allocate the memory for the decryption buffers */
  // char file_sha_rt_d[(SHA_DIGEST_LENGTH * 2) + 1]; /* Placeholder */
  char sha_hash_rt_d[(SHA_DIGEST_LENGTH * 2) + 1];

  /* Decryption Buffers */
  char file_seed_hd_d[(sizeof(file_seed_hd_e)/sizeof(int16_t)) +1];
  // char sha_hash_hd_d[(SHA_DIGEST_LENGTH * 2) + 1]; /* Placeholder */


  /* Store the sensitive information */
  if (sha1_from_en_buf_to_en_buff(file_seed_hd_e,
                                  sizeof(file_seed_hd_e),
                                  file_sha_rt_e) == NULL) {
      permitted = false;
      hwinfo_add(hardware_info, HW_SHA1, (char *)"Key-File is Missing");
  } else {

  /* Add the sha1 to the hw_info structure */
  _STRHT_DECRPT_(file_sha_rt_e, sha_hash_rt_d);
  hwinfo_add(hardware_info, HW_SHA1, sha_hash_rt_d);
  }

  if (PROTECTION >= PEN_TESTER) {
    if (!_STRHT_CMP_(file_sha_rt_e,file_sha_hd_e)) {
      #ifdef DEVEL
      printf("SHA1 Miss-Match!! \n");
      #endif
      permitted = false;
    }
  }
  #endif

  if (lv_det() || gb_det()) {
    printf("Warning Tampering Detected\n");
    permitted = false;
  }


  /* Program will NOT break execution when a wrong password
  is inserted by default. Developper mode enables this behavior */
  #ifdef DEVEL
  if (!permitted) {
    printf("This is the password you are looking for...\n"
           "( You pirate !!! )\n");
    exit(1);
  }
  #endif

  /* Add the permitted variable to the data structure */
  hwinfo_add(hardware_info, HW_AUTHORIZED,  (bool *)&permitted);

  /* Calculate the password hash */
  hash_enc(hardware_info, hash_key_e, sizeof(hash_key_e));

  if (argc == 1) {
    help(argv[0]);
  #ifdef HWD_ID
  } else if (argc == 2 && !strcmp(argv[1],"--ramkey")) {
    ram_key(_STRHT_DECRPT_(hash_key_e, hash_key_d));
    printf("%s\n", _STRHT_DECRPT_(hash_key_e, hash_key_d));
  } else if (argc == 2 && !strcmp(argv[1],"--hash")) {
    printf("%s\n", _STRHT_DECRPT_(hash_key_e, hash_key_d));
  #ifdef DEVEL
  } else if (argc == 3 && !strcmp(argv[1],"--check")) {
    if (validate_key(argv[2])) {
      printf("Key %s is Valid\n", argv[2]);
      return 0;
    } else {
      printf("Key %s is Invalid\n", argv[2]);
      return 1;
    }
  #endif
  #endif
  } else if (argc == 2 && !strcmp(argv[1],"--vhash")) {
    printf("\n[ Runtime Hardware Keys ] \n");
    #ifdef HWD_ID

    ram_key(_STRHT_DECRPT_(hash_key_e, hash_key_d));
    printf("Serial (int): %" PRIu64 "\nSerial (hex): %" PRIx64 " \n",
           serial,
           serial);
    printf("Hash Key:     %s\n", _STRHT_DECRPT_(hash_key_e, hash_key_d));
    #endif
    #ifdef MACHINE_ID
    printf("Machine-id:   %s\n",(char *)hwinfo_get_pl(hardware_info,
                                                      HW_MACHINE_ID));
    #endif
    #if defined(FILE_SEED) && defined(FILE_SHA1)
    printf("KeyFile:      %s\n", _STRHT_DECRPT_(file_seed_hd_e,
                                                file_seed_hd_d));
    printf("SHA1 Key:     %s\n", (char *)hwinfo_get_pl(hardware_info,HW_SHA1));

    #endif
  } else {
    help(argv[0]);
  }
  return 0;
}
