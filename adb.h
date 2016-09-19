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
 #include <inttypes.h>
 #include <sys/ptrace.h>

 typedef enum adb_detection {
   NODEBUGGER = 0, ///< successfull return
   DEBUGGER   = 1, ///< error
 } adb_detection_t;

 /**
  * Detect debuggers running ptrace
  *
  * @return adb_detection_t (0) if nothing is detected 1 otherwise.
  *
  */
uint8_t gb_det();

/**
 * Detect breakpoint in fucntion
 *
 * @param Addr of method that breakpoint could be set
 * @return adb_detection_t (0) if nothing is detected 1 otherwise.
 *
 */
uint8_t bp_det(uint64_t addr);

/**
 * Detect LV Preload. Used in conjuction with gb_det to dissalow overwriting
 * the ptrace method
 *
 * @return adb_detection_t (0) if nothing is detected 1 otherwise.
 *
 */
uint8_t lv_det();

 #endif
