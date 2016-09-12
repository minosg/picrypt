/*****************************************************************************\
 * Simple Test file that showcases how to used strhide                        *
 *                                                                            *
 * Author: Minos Galanakis                                                    *
 * Email: minos197@gmail.com                                                  *
 * License: GPL v3.0                                                          *
 * Project: PiCrypt                                                           *
 * File Description: Test File                                                *
 \****************************************************************************/
#define ref_string "test"
#define buff_size 32
#include "strhide.h"


int main(int argc, const char *argv[])
{
 char test_string[buff_size];

 /* Usage Help */
 if (argc !=2){
   printf ("Usage:\n./strhide sometext\n");
   return 1;
 }
 sprintf(test_string, "%s", argv[1]);

/* Buffers for encrtypted data */
 int16_t cr_string[strlen(test_string)]; ///< Binary Buffer, no need tor nul chr
 int16_t rf_string[strlen(ref_string)];  ///< Reference string buffer

 /* Buffer for decrypted string */
 char dec_string[strlen(test_string)+1]; ///< One extra space for null term

/* Encryte the user and test strings */
 encrypt_string(test_string, cr_string, sizeof(cr_string));
 encrypt_string(ref_string, rf_string, sizeof(rf_string));

/* Decrypt the user string */
 decrypt_string(cr_string, dec_string, sizeof(dec_string));
 printf("Encrypting %s stored as:\n", test_string);
 print_array(cr_string,sizeof(cr_string));
 printf("Decrypted as: \"%s\"\n", dec_string);

 if (compare_encrypted_str(rf_string,
                           cr_string,
                           sizeof(rf_string),
                           sizeof(cr_string)))
 {
   printf ("String \"%s\" Matches with refference string \"%s\" !\n",
           argv[1],
           ref_string);
 }
 return 0;
}
