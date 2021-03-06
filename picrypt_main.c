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

/* Naming convention:
 module_variable_hd/rt_e -> module where method/var is defined
                            variable name,
                            hardcoded/runtime
                            encrypted/decrypted*/

int main(int argc, char **argv)
{
  bool pc_flag_permitted_d = true;
  bool pc_flag_antitamper_d = false;
  hw_msg_page_t * pc_hardware_info_d = hw_msg_init();
  char pc_hash_key_d[HBUFF_SZ+1];
  int16_t pc_hash_key_e[HBUFF_SZ];

  /* Add breakpoint detection to critical methods */
 uint8_t pc_bpoint_dt_d;
 pc_bpoint_dt_d = (ab_breakp_det((RAM_ADDR_SZ)&hw_msg_add)+\
                   ab_breakp_det((RAM_ADDR_SZ)&pc_hash_enc)+\
                   ab_breakp_det((RAM_ADDR_SZ)&sh_encrypt_string)+\
                   ab_breakp_det((RAM_ADDR_SZ)&hw_get));

  #ifdef MACHINE_ID
  pc_bpoint_dt_d += ab_breakp_det((RAM_ADDR_SZ)&pc_soft_machine_id);
  #endif /* MACHINE_ID */
  #if defined(FILE_SEED) && defined(FILE_SHA1)
  pc_bpoint_dt_d += ab_breakp_det((RAM_ADDR_SZ)&pc_sha1_from_en_buf_to_en_buff);
   #endif /* FILE_SEED || FILE_SHA1 */
  if (pc_bpoint_dt_d != 0) {
    #ifdef DEVEL
    printf("Warning Tampering Detected (bp)\n");
    #endif /* DEVEL */
    pc_flag_antitamper_d = true;
    // TODO Make it goto somewhere
  }

  /* Detect gdb debugger and LV_PRELOAD bypass */
  if (ab_lvpreld_det() || ab_gb_det_2()) {
    #ifdef DEVEL
    printf("Warning Tampering Detected\n");
    #endif /* DEVEL */
    pc_flag_antitamper_d = true;
  }

  /* Add the result of anti-tamper detection to the structure */
  hw_msg_add(pc_hardware_info_d, HW_ANTITAMPER, (bool *)&pc_flag_antitamper_d);
  if (pc_flag_antitamper_d) {

    /* Call the user method and let him handle with antitamper without
    exposing more parts of the code */
    pc_hash_enc(pc_hardware_info_d, pc_hash_key_e, sizeof(pc_hash_key_e));
  }

  #ifdef HWD_ID
  /* Allow the user to override the detected CPU serial */
  #ifndef FAKE_SERIAL
  uint64_t pc_serial_rt_d = pc_pi_serial();
  #else
  uint64_t pc_serial_rt_d = (uint64_t)FAKE_SERIAL;
  #endif /* FAKE_SERIAL */

  /* Decrypt the Authorized CPU Serial */
  const int16_t pc_hardware_id_e[] = HWD_ID;
  char pc_hardware_id_d[CPU_SER_SIZE + 1];
  _STRHT_DECRPT_(pc_hardware_id_e, pc_hardware_id_d);
  uint64_t pc_serial_hd_d = (uint64_t)strtoull(pc_hardware_id_d, NULL, 16);

  /* Add the data to the hw_info structure */
  hw_msg_add(pc_hardware_info_d, HW_SERIAL, &pc_serial_rt_d);

  if ((PROTECTION >= SCRIPT_KIDDY) && (pc_serial_hd_d != pc_serial_rt_d)) {
    #ifdef DEVEL
    printf("Serial Miss-Match!! \n");
    #endif /* DEVEL */
    pc_flag_permitted_d = false;
  }
  #endif /* HWD_ID */
  #ifdef MACHINE_ID
  /* Allocate buffers */
  int16_t pc_machine_id_hd_e[] = MACHINE_ID;
  int16_t pc_machine_id_rt_e[MACHINE_ID_SIZE];

  /* Decryption Buffer */
  // char machine_id_hd_d[MACHINE_ID_SIZE + 1]; /* Placeholder */

  /* Exctact Current Machine ID (not sensitive) */
  char pc_machine_id_rt_d[MACHINE_ID_SIZE + 1];
  pc_soft_machine_id(pc_machine_id_rt_d);

  /* Add the machine-id to the hw_info structure */
  hw_msg_add(pc_hardware_info_d, HW_MACHINE_ID, pc_machine_id_rt_d);
  _STRHT_ENCRPT_(pc_machine_id_rt_d, pc_machine_id_rt_e);

  if (PROTECTION >= ARCH_USER) {
    if (!_STRHT_CMP_(pc_machine_id_rt_e, pc_machine_id_hd_e)) {
      #ifdef DEVEL
      printf("Machine ID Miss Match!! \n");
      #endif /* DEVEL */
      pc_flag_permitted_d = false;
    }
  }
  #endif /* MACHINE_ID */

  #if defined(FILE_SEED) && defined(FILE_SHA1)
  /* Allocate the buffers that will hide the filename and seed */
  int16_t pc_file_seed_hd_e[] = FILE_SEED;
  int16_t pc_file_sha_hd_e[] = FILE_SHA1;
  int16_t pc_file_sha_rt_e[SHA_DIGEST_LENGTH * 2];

  /* Allocate the memory for the decryption buffers */
  // char file_sha_rt_d[(SHA_DIGEST_LENGTH * 2) + 1]; /* Placeholder */
  char pc_sha_hash_rt_d[(SHA_DIGEST_LENGTH * 2) + 1];

  /* Decryption Buffers */
  #ifdef DEVEL
  char file_seed_hd_d[(sizeof(pc_file_seed_hd_e) / sizeof(int16_t)) + 1];
  #endif /* DEVEL */
  // char sha_hash_hd_d[(SHA_DIGEST_LENGTH * 2) + 1]; /* Placeholder */


  /* Store the sensitive information */
  if (pc_sha1_from_en_buf_to_en_buff(pc_file_seed_hd_e,
                                  sizeof(pc_file_seed_hd_e),
                                  pc_file_sha_rt_e) == NULL) {
      pc_flag_permitted_d = false;
      hw_msg_add(pc_hardware_info_d, HW_SHA1, (char *)"Key-File is Missing");
  } else {

  /* Add the sha1 to the hw_info structure */
  _STRHT_DECRPT_(pc_file_sha_rt_e, pc_sha_hash_rt_d);
  hw_msg_add(pc_hardware_info_d, HW_SHA1, pc_sha_hash_rt_d);
  }

  if (PROTECTION >= PEN_TESTER) {
    if (!_STRHT_CMP_(pc_file_sha_rt_e,pc_file_sha_hd_e)) {
      #ifdef DEVEL
      printf("SHA1 Miss-Match!! \n");
      #endif /* DEVEL */
      pc_flag_permitted_d = false;
    }
  }
  #endif  /* FILE SEED || FILE_SHA1 */

  /* Program will NOT break execution when a wrong password
  is inserted by default. Developper mode enables this behavior */
  #ifdef DEVEL
  if (!pc_flag_permitted_d) {
    printf("This is not the password you are looking for...\n"
           "( You pirate !!! )\n");
    exit(1);
  }
  #endif /* DEVEL */

  #ifdef INPT_TOKEN
  int16_t pc_input_token_hd_e[] = INPT_TOKEN;
  const uint16_t pc_tken_sz = sizeof(pc_input_token_hd_e) / sizeof(int16_t);
  int16_t pc_input_token_rt_e[pc_tken_sz];
  uint8_t inp_idx = 0;
  if (argc >= 4) {
    /* Go through the arguments */
    for (uint8_t k=0; k < argc; k++) {
      /* Need two extra arguments after input */
      if (!strcmp(argv[k],"--input") && (argc - k) >= 2) {
        inp_idx = k + 1;
        break;
      }
    }
    /* If input has been detected proccess it */
    if (inp_idx != 0) {
      if (strlen(argv[inp_idx]) == pc_tken_sz) {
        _STRHT_ENCRPT_(argv[inp_idx], pc_input_token_rt_e);
        if (_STRHT_CMP_(pc_input_token_rt_e, pc_input_token_hd_e)){
          hw_msg_add(pc_hardware_info_d, HW_USR_INPUT, argv[inp_idx + 1]);
        #ifdef DEVEL
        } else {
          printf("Input Token Miss-Match\n");
        #endif /* DEVEL */
        }
      #ifdef DEVEL
      } else {
        printf("Input Token Size Miss-Match\n");
      #endif /* DEVEL */
      }
    }
  }
  #endif /* INPT_TOKEN */

  /* Add the permitted variable to the data structure */
  hw_msg_add(pc_hardware_info_d, HW_AUTHORIZED,  (bool *)&pc_flag_permitted_d);

  /* Calculate the password hash */
  pc_hash_enc(pc_hardware_info_d, pc_hash_key_e, sizeof(pc_hash_key_e));

  /* Call the custom input handling method */
  #ifdef INPT_TOKEN
  if (inp_idx) {
    input_method(pc_hardware_info_d, _STRHT_DECRPT_(pc_hash_key_e, pc_hash_key_d));
  }
  #endif /* INPT_TOKEN */
  if (argc == 1) {
    pc_help(argv[0]);
  #ifdef DEVEL
  } else if (argc == 2 && !strcmp(argv[1],"--hash")) {
    printf("%s\n", _STRHT_DECRPT_(pc_hash_key_e, pc_hash_key_d));

  } else if (argc == 3 && !strcmp(argv[1],"--check")) {
    if (pc_validate_key(argv[2])) {
      printf("Key %s is Valid\n", argv[2]);
      return 0;
    } else {
      printf("Key %s is Invalid\n", argv[2]);
      return 1;
    }
  #endif /* DEVEL */
  } else if (argc == 3 && !strcmp(argv[1],"--encrypt")) {
    const char *path = argv[2];
    if (lk_sanitize_input((char *)path)) {
      _STRHT_DECRPT_(pc_hash_key_e, pc_hash_key_d);
      lk_encrypt(pc_hash_key_d, path);
    } else {
      printf("Path %s is not of acceptedable format\n", path);
      exit(1);
    }
  } else if (argc == 3 && !strcmp(argv[1],"--mount")) {
    const char *path = argv[2];
    _STRHT_DECRPT_(pc_hash_key_e, pc_hash_key_d);
    if (lk_sanitize_input((char *)path)) {
      lk_mount(pc_hash_key_d, path);
    } else {
      printf("Path %s is not of acceptedable format\n", path);
      exit(1);
    }
  #ifdef DEVEL
  } else if (argc == 2 && !strcmp(argv[1],"--vhash")) {
    printf("\n[ Runtime Hardware Keys ] \n");
    #ifdef HWD_ID

    printf("Serial (int): %" PRIu64 "\nSerial (hex): %" PRIx64 " \n",
           pc_serial_rt_d,
           pc_serial_rt_d);
    printf("Hash Key:     %s\n", _STRHT_DECRPT_(pc_hash_key_e, pc_hash_key_d));
    #endif /* HWD_ID */
    #ifdef MACHINE_ID
    printf("Machine-id:   %s\n",(char *)hw_get(pc_hardware_info_d,
                                                      HW_MACHINE_ID));
    #endif /* MACHINE_ID */
    #if defined(FILE_SEED) && defined(FILE_SHA1)
    printf("KeyFile:      %s\n", _STRHT_DECRPT_(pc_file_seed_hd_e,
                                                file_seed_hd_d));
    printf("SHA1 Key:     %s\n", (char *)hw_get(pc_hardware_info_d,
                                                       HW_SHA1));
    #endif /* FILE SEED || FILE_SHA1 */
  #endif /* DEVEL */
  } else {
    pc_help(argv[0]);
  }
  return 0;
}
