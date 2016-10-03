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
#ifndef _HW_AUTH_H_
#define _HW_AUTH_H_

#define APP_ID     "FF112233"                         ///< Applcation ID
#define HWD_ID     "aabbccdd"                         ///< CPU_Serial
#define MACHINE_ID "4b7eaab33d5b1847a77aceb0550c3474" ///< Soft ID
#define FILE_SEED  "/etc/fstab"                       ///< File for SHA SEED
#define FILE_SHA1  "9b0412be89c672159deee5f041d9b60d24a3944f"///< sha of file
#define HWD_SRC     "/dev/ttyUSB0"                    ///< Port of HW dongle
#define PI_VER     3                                  ///< PI Board Version
#define PROTECTION PEN_TESTER                          ///< Level of protection
#define INPT_TOKEN "knockknock"                       ///< Permit input from cmd 

#define _STRHT_USR_SALT 0x71                          ///< Override String Salt

/* Special definitions  */
#define FAKE_SERIAL     0xaabbccdd                    ///< (Devel) Fake serial
//#define LONG_HASH                                   ///< 2x the passwd length
//#define DEVEL                                       ///< Developper build
#endif /* _HW_AUTH_H_ */
/*****************************************************************************\
 *                           Notes                                            *
 \****************************************************************************\

 * Supported Protection Levels :
CARE_BEAR     ///< No Checks
SCRIPT_KIDDY  ///< Only CPU Serial Check
ARCH_USER     ///< CPU Serial and Software Check
PEN_TESTER    ///< CPU Serial, Software, and Random File SHA
TIN_FOIL_HAT  ///< Everything and a handrware dongle key

* APP_ID and HARDWARE_SOURCE are for future changes, not used in currest state
of code.

* _STRHT_USR_SALT string obfuscation salt is not required but recommended
to increase security. Small numbers provide higher entropy to the random data
which is more secure. Large numbers are harder to bruteforce. Pick your caveat.
 */
