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
 * File Description: Stuctured Data payload and linked list methods (Header)  *
 \****************************************************************************/

#ifndef _HWINFO_H_
#define _HWINFO_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>

#define __STDC_FORMAT_MACROS
/************************
   Enums
************************/

typedef enum hw_data_type {
  HW_EMPTY         = 0, ///< No HW info
  HW_SERIAL        = 1, ///< CPU Serial
  HW_MACHINE_ID    = 2, ///< Software Machine ID
  HW_SHA1          = 3, ///< Calculated SHA1 hash
  HW_DNGLE_KEY     = 4, ///< CPU Serial, Software, and Random File SHA
  HW_AUTHORIZED    = 5, ///< Pass the result of the hw detection tests.
  HW_ANTITAMPER    = 6, ///< Pass the result of Anti Tamper detection tests.
  HW_USR_INPUT     = 7  ///< Pass user input to logic
} hw_data_type_t;

/**
 * Return Status
 */
typedef enum hw_ret_status {
  HW_SUCESS = 0, ///< successfull return
  HW_MEM    = 1, ///< Could not allocate memory
  HW_INDEX  = 2, ///< Out of index range
  HW_FAIL   = 3, ///< Other Error
} hw_ret_status_t;

/************************
          Struct
************************/
typedef struct hw_msg_page {
    hw_data_type_t          hw_type;
    void *                  hw_payload;
    uint8_t                 hw_entries;
    struct hw_msg_page *  next;
} hw_msg_page_t;

/************************
         Methods
************************/

/**
 * Initialize a new hardware info structure. It will allocate memory and
 * mark the type field as HW_EMPTY.
 *
 * @return A pointer to the first page of the allocated linked list
 */
hw_msg_page_t * hw_msg_init();

/**
 * Add an entry to the harware info dataset.
 *
 * Data is added as a pointer to the preallocated memory location that they
 * are stored. They are NOT copied over inside the structure. Dereferencing
 * the voide pointer based on type is needed.
 *
 * @param hw_info_struct Point of hwinfo structure to store the data.
 * @param type Entry data type.
 * @param hw_payload Pointer to the buffer containing the payload.
 *
 * @return HW_SUCESS if successfull error number if failed
 */
hw_ret_status_t hw_msg_add(hw_msg_page_t * hw_info_struct,
                             hw_data_type_t type,
                             void * hw_payload);

/**
 * Returns the adress of the payload for given record type.
 *
 * @param hw_info_struct Point of hwinfo structure to store the data.
 * @param type Entry data type.
 *
 * @return (void *) of the allocated buffer if entry exists or NULL if not
 */
void * hw_get(hw_msg_page_t * hw_info_struct,
                     hw_data_type_t type);

/**
 * Delete an entry of the data structure and free the alocated memory
 *
 * @param hw_info_struct Address of hw_info_struct pointer (use &) .
 * @param type Entry data type.
 *
 * @return hw_ret_status_t based on status.
 */
hw_ret_status_t hw_delete(hw_msg_page_t ** hw_info_struct,
                              hw_data_type_t type);

/**
 * Delete every single memory block allocated to the data structure.
 *
 * @param hw_info_struct Point of hwinfo structure to store the data.
 *
 * @return hw_ret_status_t based on status.
 */
void hw_free(hw_msg_page_t * hw_info_struct);

/**
 * Print out a hardware info data structure.
 *
 * @param hw_info_struct Point of hwinfo structure to store the data.
 *
 */
void hw_cat(hw_msg_page_t * hw_info_struct);

#endif /* _HWINFO_H_ */
