/*****************************************************************************\
 * Simple Test file that showcases how to used strhide                        *
 *                                                                            *
 * Author: Minos Galanakis                                                    *
 * Email: minos197@gmail.com                                                  *
 * License: GPL v3.0                                                          *
 * Project: PiCrypt                                                           *
 * File Description: Test File                                                *
 \****************************************************************************/

#include "strhide.h"

int main(int argc, const char *argv[])
{
 char test_string[32];
 /* Usage Help */
 if (argc !=2){
   printf ("Usage:\n./strhide sometext\n");
   return 1;
 }
 sprintf(test_string, "%s", argv[1]);

 int16_t cr_string[strlen(test_string)]; ///< Binary Buffer, no need tor nul char
 char dec_string[strlen(test_string)+1]; ///< One extra space for null termination

 random_fill_array(cr_string, sizeof(cr_string));
 printf("Random Seed\n");
 print_array(cr_string,sizeof(cr_string));


 encrypt_string(test_string, cr_string, sizeof(cr_string));
 decrypt_string(cr_string, dec_string, sizeof(dec_string));

 printf("Encrypting %s stored as:\n", test_string);
 print_array(cr_string,sizeof(cr_string));
 printf("Decrypted as: \"%s\"\n", dec_string);

 return 0;
}
