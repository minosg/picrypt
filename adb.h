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
 * File Description: Custom User locking routines                             *
 \****************************************************************************/

 #ifndef _ADB_H_
 #define _ADB_H_
 #define _POSIX_C_SOURCE  200811L
 #include <stdio.h>
 #include <stdlib.h>
 #include <stdint.h>
 #include <unistd.h>
 #include <inttypes.h>
 #include <sys/ptrace.h>
 #include <sys/types.h>
 #include <sys/wait.h>
 #include <sys/prctl.h>

 #if __x86_64__
 #define RAM_ADDR_SZ uint64_t
 #else
 #define RAM_ADDR_SZ uint32_t
 #endif

 typedef enum ad_detection {
   NODEBUGGER = 0, ///< successfull return
   DEBUGGER   = 1, ///< error
 } ad_detection_t;

 /**
  * Detect debuggers running ptrace
  *
  * @return ad_detection_t (0) if nothing is detected 1 otherwise.
  *
  */
uint8_t ab_gb_det();

/**
 * Detect debuggers running ptrace without breaking execve commands
 *
 * @return ad_detection_t (0) if nothing is detected 1 otherwise.
 *
 */
uint8_t  ab_gb_det_2();

/**
 * Detect breakpoint in fucntion
 *
 * @param Addr of method that breakpoint could be set
 * @return ad_detection_t (0) if nothing is detected 1 otherwise.
 *
 */
uint8_t ab_breakp_det(RAM_ADDR_SZ addr);

/**
 * Detect LV Preload. Used in conjuction with ab_gb_det to dissalow overwriting
 * the ptrace method
 *
 * @return ad_detection_t (0) if nothing is detected 1 otherwise.
 *
 */
uint8_t ab_lvpreld_det();

 #endif
