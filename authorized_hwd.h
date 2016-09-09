/*****************************************************************************\
 * PiCrpy is a software key generator for ecryptfs locked system.             *
 * Since the program is meant to unlock the protected area, it has to be      *
 * decrypted itself but will perform a set of  hardware tests before producing*
 * the unlock key.                                                            *
 *                                                                            *
 * Author: Minos Galanakis                                                    *
 * Email: minos197@gmail.com                                                  *
 * License: GPL v3.0                                                          *
 * Project: PiCrypt                                                           *
 * File Description: User input parameters                                    *
 \****************************************************************************/
/* Those fields need to be completed  by the user */

#define HWD_ID "aabbccdd"                              ///< CPU_Serial
#define MACHINE_ID "9a8d3bccfe387dae290bf94c121207bec" ///< Soft ID
#define FILE_SEED "/etc/fstab"                         ///< File for SHA SEED
#define FILE_SHA1 "9809a6a289038cac0a14bc50b65e2e228818409e"
#define HARWARE_SOURCE "/dev/ttyUSB0"                  ///< Port of HW dongle
#define GODMODE 1                                      ///< Will be removed
#define PI_VER 2                                       ///< PI Board Version
#define PROTECTION CARE_BEAR                           ///< Level of protection
#define _STRHT_USR_SALT 0x01                           ///< Override String Salt
