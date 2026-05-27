/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "es9.h"
#include "es10.h"

typedef struct notification_group_node_s {
    fqdn_t notification_address;
    uint32_t* sequence_number_list;
    size_t sequence_number_list_size;
    struct notification_group_node_s* next;
} notification_group_node_t;

/**
 * This function processes all pending UICC notifications. 
 * Notifications are grouped by SMDP+ and sorted by sequence number before being sent to SMDP+ and removed from the UICC.
 * The execution process that follows this function is described in section 3.5 of the SGP.22
 * 
 * @param[in] es9 A valid ES9 handle from a successful call to es9__ctor().
 * @param[in] es10 A valid ES10 handle from a successful call to es10__ctor().
 * 
 * @return eOk in case the notifications delivery procedure has been executed successfully. Otherwise, an error code is returned.
*/
ErrCode notifications_delivery__all_notifications(es9_t* const es9, es10_t* const es10);

/**
 * This function sends a PendingNotification to the SMDP+ and removes it from the UICC (optional, can be specified in the function parameters).
 * 
 * @param[in] es9 A valid ES9 handle from a successful call to es9__ctor().
 * @param[in] es10 A valid ES10 handle from a successful call to es10__ctor().
 * @param[in] remove_after_send True if the notification will be removed from the UICC once it is successfully sent to SMDP+.
 * @param[in] pending_notification pointer to a byte array with the PendingNotification TLV to process.
 * @param[in] pending_notification_size size of the PendingNotification TLV byte array.
 * 
 * @return eOk in case the delivery of the notification has been executed successfully. Otherwise, an error code is returned.
*/
ErrCode notifications_delivery__single_notification(es9_t* const es9, es10_t* const es10, const bool remove_after_send, const uint8_t* pending_notification, const uint32_t pending_notification_size);

/**
 * This function removes a notification from the UICC by its sequence number.
 * 
 * @param[in] es10 A valid ES10 handle from a successful call to es10__ctor().
 * @param[in] sequence_number Sequence number of the notification to be removed.
 * 
 * @return eOk in case the notification has been removed successfully. Otherwise, an error code is returned.
*/
ErrCode notifications_delivery__remove_notification(es10_t* const es10, const uint32_t sequence_number);

/**
 * This function removes all pending notifications from the UICC.
 * 
 * @param[in] es10 A valid ES10 handle from a successful call to es10__ctor().
 * 
 * @return eOk in case all notifications have been removed successfully. Otherwise, an error code is returned.
*/
ErrCode notifications_delivery__remove_all_notifications(es10_t* const es10);

/**
 * This function removes a PendingNotification from the UICC.
 * 
 * @param[in] es10 A valid ES10 handle from a successful call to es10__ctor().
 * @param[in] pending_notification pointer to a byte array with the PendingNotification TLV to be removed.
 * @param[in] pending_notification_size size of the PendingNotification TLV byte array.
 * 
 * @return eOk in case the notification has been removed successfully. Otherwise, an error code is returned.
*/
ErrCode notifications_delivery__remove_pending_notification(es10_t* const es10, const uint8_t* pending_notification, const uint32_t pending_notification_size);

/**
 * Initializes the notification group list for notification delivery management.
 *
 * @param[in] es10 A valid ES10 handle from a successful call to es10__ctor().
 * @param[out] notifications_list Double pointer to the notification group node list to be initialized.
 *
 * @return eOk if the notification group list is initialized successfully. Otherwise, an error code is returned.
*/
ErrCode notifications_delivery__initialize_notifications_group_list(es10_t* const es10, notification_group_node_t** notifications_list);

/**
 * Delivers a single notification based on the specified sequence number.
 *
 * @param[in] es9 A valid ES9 handle for communication with the backend service.
 * @param[in] es10 A valid ES10 handle from a successful call to es10__ctor().
 * @param[in] es10_is_init Boolean flag indicating whether the ES10 module has been initialized.
 * @param[in] remove_after_send Boolean flag indicating whether to remove the notification after successful delivery.
 * @param[in] smdp_address Pointer to a string containing the SM-DP+ server address.
 * @param[in] seq_number Sequence number of the single notification to be delivered.
 *
 * @return eOk if the single notification is delivered successfully. Otherwise, an error code is returned.
*/
ErrCode notifications_delivery__seq_number_single_notification_delivery(es9_t* const es9, es10_t* const es10, bool es10_is_init, bool remove_after_send, const char* smdp_address, uint32_t seq_number);

/**
 * Frees the entire linked list of notifications and releases all allocated resources.
 *
 * @param[in,out] head  Double pointer to the head node of the notification linked list.
 *                      Set to NULL after all memory is freed successfully.
 *
 * @return None
*/
void notifications_delivery__free_notification_list(notification_group_node_t** head);
