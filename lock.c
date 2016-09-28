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
 * File Description: Handles System operations related to unlocking           *
 * locking the directories                                                    *
 \****************************************************************************/

#include "lock.h"

/* Mount an encrypted path with provided key */
uint8_t lk_mount(const char * key, const char * path)
{
  /* Create a big enough buffer to store the command*/
  const uint16_t cmd_sz = LK_MNT_CMD_MAX_SZ +
                          (LK_SIG_SZ * 2) +
                          LK_SER_SZ +
                          strlen(LK_NO_STDOUT) +
                          (strlen(path) * 2);
  char cmd[cmd_sz];
  char sigs[2][LK_SIG_SZ];
  /* Ensure root permissions */
  if (!lk_check_root()){
       printf("Please run with root permissions\n");
       exit(1);
  }

  /* Add the key to the keychain */
  lk_add_keyhcain(key, sigs);

  /* Compose the decrypt command */
  snprintf(cmd,
           sizeof(cmd),
           "/bin/mount -t ecryptfs -o verbose=yes,"
           "key=passphrase:passphrase_passwd=%s,ecryptfs_fnek_sig=%s,"
           "ecryptfs_enable_filename_crypto=y,ecryptfs_sig=%s,"
           "no_sig_cache=y,ecryptfs_cipher=aes,ecryptfs_key_bytes=16,"
           "ecryptfs_passthrough=n %s %s > %s",
           key,
           sigs[0],
           sigs[1],
           path,
           path,
           LK_NO_STDOUT);

  /* Mount the filesystem */
  return system(cmd);
}

/* Encrypt a directory  with provided key */
 void lk_encrypt(const char * key, const char* path)
 {
   /* Just create a big enough generic purpose buffer */
   const uint16_t cmd_sz = LK_MNT_CMD_MAX_SZ +
                           (LK_SIG_SZ * 2) +
                           LK_SER_SZ +
                           (strlen(path) * 2);
   char cmd[cmd_sz];
   char sigs[2][LK_SIG_SZ];

   /* Ensure root permissions */
   if (!lk_check_root()){
        printf("Please run with root permissions\n");
        exit(1);
   }

   /* Mkdir will return 1 if directory exists */
   if ( mkdir(path, 0700) != 0) {
       printf("Copying files to encrypted directory..\n"
              "\nWARNING!. This is a RAM limited operation and will fail\n if"
              "size of data in %s is greater than memory.\n\n", path);

        /* Make the temporray folder*/
        mkdir(LK_TMP_FOLDR, 0777);

        /* Copy files over */
        snprintf(cmd,
                 sizeof(cmd),
                 "/bin/cp -prf %s/* %s > %s || :",
                 path,
                LK_TMP_FOLDR,
                LK_NO_STDOUT);
        if (!system(cmd)) {
          printf("Moving files from %s to temporary directory (%s)\n",
                  path,
                  LK_TMP_FOLDR);
        } else {
          printf("Error Copying files to temporary directory: %s\n",
                  LK_TMP_FOLDR);
          exit(1);
        }
        memset(cmd, 0, sizeof(cmd));
    }

    snprintf(cmd,
             sizeof(cmd),
             "/bin/rm -rf %s  > %s && /bin/mkdir %s > %s",
             path, LK_NO_STDOUT, path, LK_NO_STDOUT);
    system(cmd);
    memset(cmd, 0, sizeof(cmd));

   /* Add the key to the keychain */
    lk_add_keyhcain(key, sigs);

    /* Encrypt the Folder */
    snprintf(cmd,
            sizeof(cmd),
            "/bin/mount -t ecryptfs -o verbose=yes,"
            "key=passphrase:passphrase_passwd=%s,ecryptfs_fnek_sig=%s,"
            "ecryptfs_enable_filename_crypto=y,ecryptfs_sig=%s,"
            "no_sig_cache=y,ecryptfs_cipher=aes,ecryptfs_key_bytes=16,"
            "ecryptfs_passthrough=n %s %s ",
            key,
            sigs[0],
            sigs[1],
            path,
            path);
    if (system(cmd)){
      printf("Error Mounting directory\n");
    }
    memset(cmd, 0, sizeof(cmd));

    if (mkdir(LK_TMP_FOLDR, 0700) != 0) {
      printf("Moving files from temporary directory (%s) to %s\n",
              LK_TMP_FOLDR,
              path);
      /* Copy files over */
      snprintf(cmd,
               sizeof(cmd),
               "/bin/cp -prf %s* %s > %s && rm -rf %s > %s",
               LK_TMP_FOLDR, path, LK_NO_STDOUT, LK_TMP_FOLDR, LK_NO_STDOUT);
      system(cmd);
    }
 }

/* Check is user is root */
bool lk_check_root()
{
  uid_t uid=getuid(), euid=geteuid();
  if (uid == 0 || euid == 0) {
    return true;
  } else {
    return false;
  }
}

/* Add a key to keychain */
char * lk_add_keyhcain(const char * key, char output[][LK_SIG_SZ])
{
  const uint8_t hdr_len = strlen("Inserted") + 1;
  const uint8_t buff_sz = 128;

  char cmd[LK_CMD_MIN_SZ];
  char tmp_headr[hdr_len];
  char buffer[buff_sz];
  uint8_t out_idx = 0;
  FILE* fk_stdout;

  /* Compose the command */
  snprintf(cmd,
           LK_CMD_MIN_SZ,
           "printf \"%s\" \"passphrase\" |"
           "/usr/bin/ecryptfs-add-passphrase --fnek\n",
           key);
  /* Run the command */
  if (!(fk_stdout = popen(cmd, "r"))) {
    printf("Error: Failed to add key to keychain\n");
    return NULL;
  }
  /* Parse output */
  while (fgets(buffer, buff_sz, fk_stdout) != NULL) {

      /* If the line contains the work inserted */
      snprintf (tmp_headr, 9, "%s", buffer);
      if (!strcmp(tmp_headr, "Inserted")) {
        snprintf (output[out_idx], LK_SIG_SZ, "%s", buffer + LK_SIG_OFFSET);
        out_idx++;
      }
      memset(tmp_headr, 0, 9);
  }
  return output[1];
}

/* Return True if path is of accepted format */
bool lk_sanitize_input(char * path)
{
  const uint16_t slen = strlen(path);
  if (path == NULL) return false;

  /* If first element is not / (absolute_path) reject it */
  if (path[0] != 0x2F) {
    return false;
  }
  for(uint16_t i=0; i < slen; i++) {
    /* If last element is / remove it */
    if (i == (slen - 1) &&  path[i] == 0x2F) {
      path[i] = 0;
    }
     /* Capture & and | chars */
     if (path[i] == 0x26 || path[i] == 0x7C) {
       return false;
     }
     /* Capture < and > chars */
     if (path[i] == 0x3E || path[i] == 0x3C) {
       return false;
     }
  }
  return true;
}
