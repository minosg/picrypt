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
 * File Description: Anti Debugging Method Implementation                     *
 \****************************************************************************/

#include "adb.h"

 /* Detect GDB presence */
 uint8_t gb_det()
 {
   if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
     return 1;
   }
   return 0;
 }

 /* Detect breakpoint in fucntions */
 uint8_t bp_det(RAM_ADDR_SZ addr)
 {
   if ((*(volatile RAM_ADDR_SZ *)((RAM_ADDR_SZ)addr + 4) & 0xff) == 0xcc) {
         return 1;
         exit(1);
   }
   return 0;
 }

 /* Detect lv preload */
 uint8_t lv_det()
 {
   if(getenv("LD_PRELOAD")) return 1;
   return 0;
 }
