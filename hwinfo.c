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
 * File Description: Stuctured Data payload and linked list methods           *
 \****************************************************************************/

#include "hwinfo.h"

/* Initialize empty strucutre */
hwd_nfo_param_t * hwinfo_init()
{
  hwd_nfo_param_t * head = NULL;
  head = malloc(sizeof(hwd_nfo_param_t));
  if (head == NULL) {
    printf("Could not allocate memory\n");
    return NULL;
  }
  head->hw_type = HW_EMPTY;
  head->hw_payload = NULL;
  head->next = NULL;
  head->hw_entries=0;
  return head;
}

/* Add entry to structure */
hw_ret_status_t hwinfo_add(hwd_nfo_param_t * hw_info_struct,
                           hwd_nfo_type_t type,
                           void * hw_payload)
{
    /* Get a moving cursor */
    hwd_nfo_param_t * last = hw_info_struct;;
    hwd_nfo_param_t * seek = hw_info_struct;
    uint8_t page_no = hw_info_struct->hw_entries;

    /* Iterate through the linked list and increment number of elements */
    while (seek != NULL){
      seek->hw_entries = page_no + 1;
      /* Kep a copy of last valid pointer before next step */
      last = seek;
      seek = seek->next;
    }

    /* When the memory is already allocated with an empty initialized list */
    if (last == hw_info_struct && last->hw_type == HW_EMPTY) {
        last->hw_type=type;
        last->hw_payload=hw_payload;
    } else {
      last->next = malloc(sizeof(hwd_nfo_param_t));
      if (last->next == NULL) return HW_MEM;
      last->next->hw_type=type;
      last->next->hw_payload=hw_payload;
      last->next->hw_entries = page_no + 1;
      last->next->next=NULL;
    }
    return HW_SUCESS;
  }


/* Get payload from entry label */
void * hwinfo_get_pl(hwd_nfo_param_t * hw_info_struct, hwd_nfo_type_t type)
{
  hwd_nfo_param_t * current = hw_info_struct;
  while (current != NULL){
    if (current->hw_type==type) {
      return current->hw_payload;
    }
    current = current->next;
  }
  return NULL;
}

/* Print all elements of the structure */
void hwinfo_print(hwd_nfo_param_t * hw_info_struct)
{
  hwd_nfo_param_t * current = hw_info_struct;
  for(int i = 0;i < hw_info_struct->hw_entries;i++) {
    printf("\nPage: %d\n",i);
    printf("Entries: %d\n",current->hw_entries);
    printf("Type: %d\n",current->hw_type);
    if (current->hw_type == HW_SERIAL) {
      printf("Serial: %" PRIx64 "\n", *(uint64_t*)current->hw_payload);
    } else {
      printf("PL: %s\n", (char *)current->hw_payload);
    }
    current = current->next;
  }
  return;
}

/* Delete single entry */
hw_ret_status_t hwinfo_delete(hwd_nfo_param_t ** hw_info_struct,
                              hwd_nfo_type_t type)
{
  hwd_nfo_param_t * current = *hw_info_struct;

  while (current != NULL){
     /* If the first element is the one we delete */
    if ((*hw_info_struct)->hw_type==type) {
      if (current->next != NULL) *hw_info_struct = current->next;
      free(current);
      break;
    } else {
        if (current->next->hw_type == type) {
          current->next = current->next->next;
          free(current->next);
          break;
        }
    }
    current = current->next;
  }
  current = *hw_info_struct;
  uint8_t pages = --(*hw_info_struct)->hw_entries;

  while (current != NULL){
    current->hw_entries=pages;
    current= current->next;
  }
  return HW_SUCESS;
}

/* Delete Everything */
void hwinfo_dealloc(hwd_nfo_param_t * hw_info_struct)
{
  hwd_nfo_param_t * current = hw_info_struct;
  hwd_nfo_param_t * following = hw_info_struct;
  while (current != NULL) {
      following = current->next;
      free(current);
      if (following == NULL) break;
      current = following;
  }
}
