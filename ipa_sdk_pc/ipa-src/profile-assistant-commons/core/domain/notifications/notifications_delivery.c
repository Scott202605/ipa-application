/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <stdlib.h>

#include "notifications_delivery.h"
#include "es10_tlv_extractor.h"
#include "memory_manager.h"
#include "log.h"


static ErrCode notifications_delivery__send_notification_to_smdp(es9_t* const es9, const char* smdp_address, const uint8_t* pending_notification, const uint32_t pending_notification_size);
static ErrCode notifications_delivery__remove_notification_from_uicc(es10_t* const es10, const bool es10_is_init, uint32_t sequence_number);
static ErrCode notifications_delivery__single_notification_delivery(es9_t* const es9, es10_t* const es10, bool es10_is_init, bool remove_after_send, const char* smdp_address, uint32_t seq_number, const uint8_t* ptr, const uint32_t size);
static ErrCode notifications_delivery__retrieve_notifications_list(es10_t* const es10, bool es10_is_init, const retrieve_notifications_list_request_t* request, uint8_t** response, uint32_t* response_size);
static ErrCode notifications_delivery__add_pending_notification_to_list(const uint8_t* pending_notification, uint32_t pending_notification_size, notification_group_node_t** notification_list);
static ErrCode notifications_delivery__add_notification_metadata_to_list(const notification_metadata_t* notification_metadata, notification_group_node_t** notification_list);
static ErrCode notifications_delivery__add_next_node(notification_group_node_t* last_node, const fqdn_t* new_node_smdp_address, const uint32_t new_node_seq_number);
static ErrCode notifications_delivery__create_new_node(const fqdn_t* smdp_address, const uint32_t seq_number, notification_group_node_t** new_node);
static ErrCode notifications_delivery__add_sequence_number_to_node(const uint32_t seq_number, notification_group_node_t* node);
static int notifications_delivery__sequence_number_compare_function(const void* a, const void* b);
static void notifications_delivery__sort_notifications_list_by_sequence_number(notification_group_node_t* head);


ErrCode notifications_delivery__all_notifications(es9_t* const es9, es10_t* const es10) {
    ErrCode rc;
    int err;
    uint32_t i;
    notification_group_node_t* notifications_list = NULL;
    notification_group_node_t* current_node;
    bool notification_delivery_failure;

    /* Initialize the Notifications group list */
    if ((rc = notifications_delivery__initialize_notifications_group_list(es10, &notifications_list)) != eOk) {
        LOGE("[notifications_delivery__all_notifications] Error initializing the notifications list, rc %d", rc);
        return rc;
    }

    /* Initialize the ES10 interface (to avoid init/deinit in each notification)*/
    if ((err = es10__init(es10)) < 0) {
        LOGE("[notifications_delivery__all_notifications] Error initializing the ES10 interface, err %d", err);
        notifications_delivery__free_notification_list(&notifications_list);
        return eFatal;
    }

    /* Deliver all the notifications for each SMDP+ */
    current_node = notifications_list;
    while (current_node) {
        notification_delivery_failure = false;
        for (i = 0; i < current_node->sequence_number_list_size && !notification_delivery_failure; i++) {
            if ((rc = notifications_delivery__seq_number_single_notification_delivery(es9, es10, true, true, current_node->notification_address.fqdn, current_node->sequence_number_list[i])) != eOk) {
                LOGE("[notifications_delivery__all_notifications] Error on deliver the %u notification to the SMDP+ '%s'. Skipping the remaining pending notifications for this SMDP+", current_node->sequence_number_list[i], current_node->notification_address.fqdn);
                notification_delivery_failure = true;
            }
        }
        current_node = current_node->next;
    }
    notifications_delivery__free_notification_list(&notifications_list);

    /* Deinitialize the ES10 interface */
    if ((err = es10__deinit(es10)) < 0) {
        LOGW("[notifications_delivery__all_notifications] Error deinitializing the ES10 interface, err %d", err);
    }
    LOGI("All notifications have been processed");

    return eOk;
}

ErrCode notifications_delivery__single_notification(es9_t* const es9, es10_t* const es10, const bool remove_after_send, const uint8_t* pending_notification, const uint32_t pending_notification_size) {
    ErrCode rc;
    notification_metadata_t metadata;

    if ((rc = es10_tlv_extractor__notification_metadata_from_pending_notification(pending_notification, pending_notification_size, &metadata)) != eOk) {
        LOGE("[notifications_delivery__single_notification] Error extracting the NotificationMetadata from the PendingNotification, rc %d", rc);
        return rc;
    }

    return notifications_delivery__single_notification_delivery(es9, es10, false, remove_after_send, metadata.notification_address.fqdn, metadata.seq_number, pending_notification, pending_notification_size);
}

ErrCode notifications_delivery__remove_notification(es10_t* const es10, const uint32_t sequence_number) {
    return notifications_delivery__remove_notification_from_uicc(es10, false, sequence_number);
}

ErrCode notifications_delivery__remove_all_notifications(es10_t* const es10) {
    ErrCode rc;
    int err;
    uint32_t i;
    notification_group_node_t* notifications_list = NULL;
    notification_group_node_t* current_node;

    /* Initialize the Notifications group list */
    if ((rc = notifications_delivery__initialize_notifications_group_list(es10, &notifications_list)) != eOk) {
        LOGE("[notifications_delivery__remove_all_notifications] Error initializing the notifications list, rc %d", rc);
        return rc;
    }

    /* Initialize the ES10 interface (to avoid init/deinit in each notification)*/
    if ((err = es10__init(es10)) < 0) {
        LOGE("[notifications_delivery__remove_all_notifications] Error initializing the ES10 interface, err %d", err);
        notifications_delivery__free_notification_list(&notifications_list);
        return eFatal;
    }

    /* Remove all the notifications for each SMDP+ */
    current_node = notifications_list;
    while (current_node) {
        for (i = 0; i < current_node->sequence_number_list_size; i++) {
            if ((rc = notifications_delivery__remove_notification_from_uicc(es10, true, current_node->sequence_number_list[i])) != eOk) {
                LOGE("[notifications_delivery__remove_all_notifications] Error removing the notification with sequence number %u, rc %d", current_node->sequence_number_list[i], rc);
            }
        }
        current_node = current_node->next;
    }
    notifications_delivery__free_notification_list(&notifications_list);

    /* Deinitialize the ES10 interface */
    if ((err = es10__deinit(es10)) < 0) {
        LOGW("[notifications_delivery__remove_all_notifications] Error deinitializing the ES10 interface, err %d", err);
    }
    LOGI("All notifications have been removed");

    return eOk;
}

ErrCode notifications_delivery__remove_pending_notification(es10_t* const es10, const uint8_t* pending_notification, const uint32_t pending_notification_size) {
    ErrCode rc;
    notification_metadata_t notification_metadata;

    if ((rc = es10_tlv_extractor__notification_metadata_from_pending_notification(pending_notification, pending_notification_size, &notification_metadata)) != eOk) {
        LOGE("[notifications_delivery__remove_pending_notification] Error extracting the NotificationMetadata from the PendingNotification");
        return rc;
    }

    return notifications_delivery__remove_notification(es10, notification_metadata.seq_number);
}

static ErrCode notifications_delivery__send_notification_to_smdp(es9_t* const es9, const char* smdp_address, const uint8_t* pending_notification, const uint32_t pending_notification_size) {
    ErrCode rc;

    /* Check input parameters */
    if (!pending_notification || 0 == pending_notification_size) {
        LOGE("[notifications_delivery__send_notification_to_smdp] The PendingNotification is empty/null");
        return eBadArg;
    }
    if (!smdp_address || 0 == strlen(smdp_address)) {
        LOGE("[notifications_delivery__send_notification_to_smdp] The SMDP+ Address is empty/null");
        return eBadArg;
    }

    /* Send the notification to the SMDP+ */
    if ((rc = es9__handle_notification(es9, smdp_address, pending_notification, pending_notification_size)) != eOk) {
        LOGE("[notifications_delivery__send_notification_to_smdp] Error sending the notification to the SMDP+, rc %d", rc);
        return rc;
    }

    return rc;
}

static ErrCode notifications_delivery__remove_notification_from_uicc(es10_t* const es10, const bool es10_is_init, uint32_t sequence_number) {
    int err;
    ErrCode rc;
    uint8_t* delete_notification_response;
    uint32_t delete_notification_size;
    notification_sent_request_t notification_sent_request = {
        .seq_number = sequence_number
    };
    notification_sent_response_t notification_sent_response;

    if (!es10_is_init) {
        if ((err = es10__init(es10)) < 0) {
            LOGE("[notifications_delivery__remove_notification_from_uicc] Error initializing the ES10 interface, err %d", err);
            return eFatal;
        }
    }

    /* Execute the ES10.RemoveNotificationFromList */
    if ((err = es10__remove_notification_from_list(es10, &notification_sent_request, &delete_notification_response, &delete_notification_size)) < 0) {
        LOGE("[notifications_delivery__remove_notification_from_uicc] ES10.RemoveNotificationFromList failed, err %d", err);
    }

    if (!es10_is_init) {
        if (es10__deinit(es10) < 0) {
            LOGE("[notifications_delivery__remove_notification_from_uicc] Error deinitializing the ES10 interface");
        }
    }

    if (err < 0) {
        LOGE("[notifications_delivery__remove_notification_from_uicc] Error on remove the notification from the uicc");
        return eFatal;
    }

    /* Parse the NotificationSentResponse */
    rc = es10_tlv_extractor__notification_sent_response(delete_notification_response, (uint32_t)delete_notification_size, &notification_sent_response);
    M_free(delete_notification_response);
    delete_notification_response = NULL;
    delete_notification_size = 0;
    if (rc != eOk) {
        LOGE("[notifications_delivery__remove_notification_from_uicc] Error on parse the NotificationSentResponse TLV, rc %d", rc);
        return rc;
    }

    /* Print the response on the terminal */
    if (DELETE_NOTIFICATION_STATUS_OK == notification_sent_response.delete_notification_status || DELETE_NOTIFICATION_STATUS_NOTHING_TO_DELETE == notification_sent_response.delete_notification_status) {
        LOGD("[notifications_delivery__remove_notification_from_uicc] Notification with SequenceNumber %u removed successfully", sequence_number);
    } else {
        LOGE("[notifications_delivery__remove_notification_from_uicc] Failed to remove the notification with SequenceNumber %u, deleteNotificationStatus %d", sequence_number, notification_sent_response.delete_notification_status);
        return eFatal;
    }

    return eOk;
}

static ErrCode notifications_delivery__single_notification_delivery(es9_t* const es9, es10_t* const es10, bool es10_is_init, bool remove_after_send, const char* smdp_address, uint32_t seq_number, const uint8_t* ptr, const uint32_t size) {
    ErrCode rc;

    if ((rc = notifications_delivery__send_notification_to_smdp(es9, smdp_address, ptr, size)) != eOk) {
        LOGE("[notifications_delivery__single_notification_delivery] Error sending the notification to the SMDP+, rc %d", rc);
        return rc;
    }
    LOGD("[notifications_delivery__single_notification_delivery] Notification sent to the SMDP+");

    if (remove_after_send) {
        if ((rc = notifications_delivery__remove_notification_from_uicc(es10, es10_is_init, seq_number)) != eOk) {
            LOGE("[notifications_delivery__single_notification_delivery] Error removing the notification from the UICC, rc %d", rc);
            return rc;
        }
    }
    LOGD("[notifications_delivery__single_notification_delivery] Notification removed from the UICC");

    return eOk;
}

ErrCode notifications_delivery__seq_number_single_notification_delivery(es9_t* const es9, es10_t* const es10, bool es10_is_init, bool remove_after_send, const char* smdp_address, uint32_t seq_number) {
    ErrCode rc;
    uint8_t* retrieve_notifications_list_response;
    uint32_t retrieve_notifications_list_response_size;
    uint8_t* pending_notification;
    uint32_t pending_notification_size;
    retrieve_notifications_list_request_t retrieve_notifications_list_request = {
        .field_is_present = {
            .search_criteria = true
        },
        .search_criteria = {
            .choice = SEQ_NUMBER_CHOICE,
            .value = {
                .seq_number = seq_number
            }
        }
    };
    asn1_list_iterator_t list_iterator;

    /* Retrieve the notification by sequence number */
    if ((rc = notifications_delivery__retrieve_notifications_list(es10, es10_is_init, &retrieve_notifications_list_request, &retrieve_notifications_list_response, &retrieve_notifications_list_response_size)) != eOk) {
        LOGE("[notifications_delivery__seq_number_single_notification_delivery] Error retrieving the notifications list from the UICC, rc %d", rc);
        return rc;
    }

    /* Get the Notifications List ASN.1 iterator*/
    if ((rc = es10_tlv_extractor__notifications_list_from_retrieve_notifications_list_response(retrieve_notifications_list_response, retrieve_notifications_list_response_size, &list_iterator)) != eOk) {
        LOGE("[notifications_delivery__seq_number_single_notification_delivery] Error on get the notifications list iterator, rc %d", rc);
        M_free(retrieve_notifications_list_response);
        return rc;
    }

    /* Get the first notification of the list */
    if ((rc = tlv_data_extractor__asn1_list_get_next(&list_iterator, &pending_notification, &pending_notification_size)) != eOk) {
        LOGE("[notifications_delivery__seq_number_single_notification_delivery] Error getting the notification %u from the list, rc %d", seq_number, rc);
        M_free(retrieve_notifications_list_response);
        return rc;
    }

    /* Make sure that there is a notification found */
    if (!pending_notification) {
        LOGE("[notifications_delivery__seq_number_single_notification_delivery] Pending notification %u not found", seq_number);
        M_free(retrieve_notifications_list_response);
        return rc;
    }

    /* Deliver the notification */
    rc = notifications_delivery__single_notification_delivery(es9, es10, es10_is_init, remove_after_send, smdp_address, seq_number, pending_notification, pending_notification_size);
    M_free(retrieve_notifications_list_response);

    return rc;
}

ErrCode notifications_delivery__initialize_notifications_group_list(es10_t* const es10, notification_group_node_t** notifications_list) {
    ErrCode rc;
    uint8_t* pending_notification;
    uint32_t pending_notification_size;
    uint8_t* retrieve_notifications_list_response;
    uint32_t retrieve_notifications_list_response_size;
    retrieve_notifications_list_request_t retrieve_notifications_list_request = {
        .field_is_present = {
            .search_criteria = false
        }
    };
    asn1_list_iterator_t list_iterator;

    /* Retrieve the notifications list response */
    if ((rc = notifications_delivery__retrieve_notifications_list(es10, false, &retrieve_notifications_list_request, &retrieve_notifications_list_response, &retrieve_notifications_list_response_size)) != eOk) {
        LOGE("[notifications_delivery__initialize_notifications_group_list] Error retrieving the notifications list from the UICC, rc %d", rc);
        return rc;
    }

    /* Get the Notifications List ASN.1 iterator*/
    if ((rc = es10_tlv_extractor__notifications_list_from_retrieve_notifications_list_response(retrieve_notifications_list_response, retrieve_notifications_list_response_size, &list_iterator)) != eOk) {
        LOGE("[notifications_delivery__initialize_notifications_group_list] Error on get the notifications list iterator, rc %d", rc);
        M_free(retrieve_notifications_list_response);
        return rc;
    }

    /* Group notifications by SMDP+ Address */
    while ((eOk == (rc = tlv_data_extractor__asn1_list_get_next(&list_iterator, &pending_notification, &pending_notification_size))) && pending_notification != NULL) {
        if ((rc = notifications_delivery__add_pending_notification_to_list(pending_notification, pending_notification_size, notifications_list)) != eOk) {
            LOGE("[notifications_delivery__initialize_notifications_group_list] Error adding a pending notification to the list, rc %d", rc);
            M_free(retrieve_notifications_list_response);
            notifications_delivery__free_notification_list(notifications_list);
            return rc;
        }
    }
    M_free(retrieve_notifications_list_response);
    retrieve_notifications_list_response = NULL;
    retrieve_notifications_list_response_size = 0;
    if (rc != eOk) {
        LOGE("[notifications_delivery__initialize_notifications_group_list] Error iterating over the ASN.1 Notifications List, rc %d", rc);
        notifications_delivery__free_notification_list(notifications_list);
        return rc;
    }

    /* Order notifications by sequence number*/
    notifications_delivery__sort_notifications_list_by_sequence_number(*notifications_list);

    return eOk;
}

static ErrCode notifications_delivery__retrieve_notifications_list(es10_t* const es10, bool es10_is_init, const retrieve_notifications_list_request_t* request, uint8_t** response, uint32_t* response_size) {
    int err;

    /* Retrieve the notifications from the UICC */
    if (!es10_is_init) {
        if ((err = es10__init(es10)) < 0) {
            LOGE("[notifications_delivery__retrieve_notifications_list] Error initializing the ES10 interface, err %d", err);
            return eFatal;
        }
    }

    if ((err = es10__retrieve_notifications_list(es10, request, response, response_size)) < 0) {
        LOGE("[notifications_delivery__retrieve_notifications_list] ES10.RetrieveNotificationsList failed, err %d", err);
    }

    if (!es10_is_init) {
        if (es10__deinit(es10) < 0) {
            LOGW("[notifications_delivery__retrieve_notifications_list] Error deinitializing the ES10 interface, err %d", err);
        }
    }

    if (err < 0) {
        LOGE("[notifications_delivery__retrieve_notifications_list] Error retrieving the notifications list from the UICC, err %d", err);
        return eFatal;
    } else {
        return eOk;
    }
}

static ErrCode notifications_delivery__add_pending_notification_to_list(const uint8_t* pending_notification, uint32_t pending_notification_size, notification_group_node_t** notification_list) {
    ErrCode rc;
    notification_metadata_t notification_metadata;

    if ((rc = es10_tlv_extractor__notification_metadata_from_pending_notification(pending_notification, pending_notification_size, &notification_metadata)) != eOk) {
        LOGE("[notifications_delivery__add_pending_notification_to_list] Error extracting the NotificationMetadata from the PendingNotification");
        return rc;
    }

    return notifications_delivery__add_notification_metadata_to_list(&notification_metadata, notification_list);
}

static ErrCode notifications_delivery__add_notification_metadata_to_list(const notification_metadata_t* notification_metadata, notification_group_node_t** notification_list) {
    notification_group_node_t* current;
    LOGD("[notifications_delivery__add_notification_metadata_to_list] sequence_number %u, notification_address '%s'", notification_metadata->seq_number, notification_metadata->notification_address.fqdn);

    /* Create the first entry of the list if the list is uninitialized */
    if (*notification_list == NULL) {
        return notifications_delivery__create_new_node(&notification_metadata->notification_address, notification_metadata->seq_number, notification_list);
    }

    /* Go to the smdp address node or to the last node in case is not found */
    current = *notification_list;
    while (strcmp(current->notification_address.fqdn, notification_metadata->notification_address.fqdn) && current->next) {
        current = current->next;
    }

    if (0 == strcmp(current->notification_address.fqdn, notification_metadata->notification_address.fqdn)) {
        // If the node of the smdp address is found, add the sequence number
        LOGD("[notifications_delivery__add_notification_metadata_to_list] '%s' node found, adding the %u sequence number", notification_metadata->notification_address.fqdn, notification_metadata->seq_number);
        return notifications_delivery__add_sequence_number_to_node(notification_metadata->seq_number, current);
    } else {
        // If the node of the smdp address is not found, add a new node to the list
        LOGD("[notifications_delivery__add_notification_metadata_to_list] '%s' node not found, creating a new one with the %u sequence number", notification_metadata->notification_address.fqdn, notification_metadata->seq_number);
        return notifications_delivery__add_next_node(current, &notification_metadata->notification_address, notification_metadata->seq_number);
    }
}

static ErrCode notifications_delivery__add_next_node(notification_group_node_t* last_node, const fqdn_t* new_node_smdp_address, const uint32_t new_node_seq_number) {
    ErrCode rc;
    notification_group_node_t* new_node;

    if ((rc = notifications_delivery__create_new_node(new_node_smdp_address, new_node_seq_number, &new_node)) != eOk) {
        LOGE("[notifications_delivery__add_next_node] Error creating the new node, rc %d", rc);
        return rc;
    }

    // Set as the next node of the last node, the new node
    last_node->next = new_node;

    return eOk;
}

static ErrCode notifications_delivery__create_new_node(const fqdn_t* smdp_address, const uint32_t seq_number, notification_group_node_t** new_node) {
    ErrCode rc;

    /* Allocate memory for the new node */
    *new_node = (notification_group_node_t*)M_calloc(1, sizeof(notification_group_node_t));
    if (!(*new_node)) {
        LOGE("[notifications_delivery__create_new_node] No memory for add the new '%s' node", smdp_address->fqdn);
        return eNoMem;
    }

    // Set the SMDP address of the node
    memcpy(&(*new_node)->notification_address, smdp_address, sizeof(fqdn_t));

    // Add the first sequence number to the node
    if ((rc = notifications_delivery__add_sequence_number_to_node(seq_number, *new_node)) != eOk) {
        LOGE("[notifications_delivery__create_new_node] Error adding the first sequence number of the node, rc %d", rc);
        M_free(*new_node);
        *new_node = NULL;
        return rc;
    }

    return eOk;
}

static ErrCode notifications_delivery__add_sequence_number_to_node(const uint32_t seq_number, notification_group_node_t* node) {
    uint32_t* ptr;

    /* Reallocate the space of the sequence number array */
    node->sequence_number_list_size++;
    ptr = (uint32_t*)M_realloc(node->sequence_number_list, node->sequence_number_list_size * sizeof(uint32_t)); // Allocate more space to add the new sequence number
    if (!ptr) {
        LOGE("[notifications_delivery__add_sequence_number_to_node] No memory for add the sequenceNumber %u to '%s' node", seq_number, node->notification_address.fqdn);
        return eNoMem;
    }

    /* Add the new sequence number into the last position */
    node->sequence_number_list = ptr;
    node->sequence_number_list[node->sequence_number_list_size - 1] = seq_number; // Add the new sequence number
    LOGD("[notifications_delivery__add_sequence_number_to_node] Sequence number %u added to '%s' node", node->sequence_number_list[node->sequence_number_list_size - 1], node->notification_address.fqdn);

    return eOk;
}

static int notifications_delivery__sequence_number_compare_function(const void* a, const void* b) {
    return (int)(*(uint32_t*)a - *(uint32_t*)b);
}

static void notifications_delivery__sort_notifications_list_by_sequence_number(notification_group_node_t* head) {
    notification_group_node_t* current_group = head;

    while (current_group) {
        qsort(current_group->sequence_number_list, current_group->sequence_number_list_size, sizeof(uint32_t), notifications_delivery__sequence_number_compare_function);
        current_group = current_group->next;
    }
}

 void notifications_delivery__free_notification_list(notification_group_node_t** head) {
    notification_group_node_t* prev;
    notification_group_node_t* current = *head;

    while (current) {
        memset(current->notification_address.fqdn, 0, sizeof(current->notification_address.fqdn));
        M_free(current->sequence_number_list);
        current->sequence_number_list = NULL;
        current->sequence_number_list_size = 0;
        prev = current;
        current = current->next;
        prev->next = NULL;
        M_free(prev);
    }
    *head = NULL;
}
