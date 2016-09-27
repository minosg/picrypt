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
 /* TODO make it work without breaking system calls*/
 uint8_t ab_gb_det()
 {
   if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
     return DEBUGGER;
   }
   return NODEBUGGER;
 }

 /* Detect GDB presence */
 uint8_t  ab_gb_det_2()
 {
   pid_t tracer_pid = fork();
   int32_t det_ret_status;
   uint8_t res;
   /* Permit the forked process to trace the parent */
   prctl(PR_SET_PTRACER, (uint32_t)getpid(), 0, 0, 0);

   if (tracer_pid == -1) {
       printf("Fork error\n");
       return -1;
     }

    /* Child Fork */
   if (tracer_pid == 0) {
       /* Get the parent's process id */
       pid_t tracee_pid = getppid();

       //* Attach to parent */
       if (ptrace(PTRACE_ATTACH, tracee_pid, NULL, NULL) == 0)
         {
           /* Wait for the parent to stop and continue it */
           waitpid(tracee_pid, NULL, 0);

           /* Detach */
           ptrace(PTRACE_DETACH, tracee_pid, NULL, NULL);

           /* Attach successfull so no other proccess is attached */
           res = NODEBUGGER;
         } else {
           /* Trace failed so something is tracking the parent */
           res = DEBUGGER;
         }
       _Exit(res);
     } else {
       /* Wait for forked ps to join and return the attach status */
       waitpid(tracer_pid, &det_ret_status, 0);
       res = WEXITSTATUS(det_ret_status);
     }
   return res;
 }

 /* Detect breakpoint in fucntions */
 uint8_t ab_breakp_det(RAM_ADDR_SZ addr)
 {
   if ((*(volatile RAM_ADDR_SZ *)((RAM_ADDR_SZ)addr + 4) & 0xff) == 0xcc) {
         return DEBUGGER;
         exit(1);
   }
   return NODEBUGGER;
 }

 /* Detect lv preload */
 uint8_t ab_lvpreld_det()
 {
   if(getenv("LD_PRELOAD")) return DEBUGGER;
   return NODEBUGGER;
 }
