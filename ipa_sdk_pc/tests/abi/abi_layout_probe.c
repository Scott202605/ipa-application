#include <stddef.h>
#include <stdio.h>

#include "ipa.h"
#include "ipa_core.h"
#include "ipa_local.h"

static int first = 1;

static void value(const char *name, size_t number) {
  printf("%s\"%s\":%zu", first ? "" : ",", name, number);
  first = 0;
}

#define TYPE(type)                                                             \
  value(#type ".size", sizeof(type));                                         \
  value(#type ".align", _Alignof(type))
#define FIELD(type, field) value(#type "." #field, offsetof(type, field))
#define ENUM(name) value(#name, (size_t)(name))

int main(void) {
  printf("{");

  TYPE(cl_config_t);
  FIELD(cl_config_t, es10_driver_selected);
  FIELD(cl_config_t, driver_id);
  FIELD(cl_config_t, log_level);
  FIELD(cl_config_t, initial_refresh_sleep);
  FIELD(cl_config_t, refresh_max_sleep);
  FIELD(cl_config_t, esipa_sync_package_retrieval_time);

  TYPE(ipa_config_mqtt_t);
  FIELD(ipa_config_mqtt_t, protocol);
  FIELD(ipa_config_mqtt_t, hostname);
  FIELD(ipa_config_mqtt_t, port);
  FIELD(ipa_config_mqtt_t, username);
  FIELD(ipa_config_mqtt_t, password);
  FIELD(ipa_config_mqtt_t, tls_config);
  FIELD(ipa_config_mqtt_t, proxy_config);

  TYPE(ipa_config_lwm2m_t);
  FIELD(ipa_config_lwm2m_t, hostname);
  FIELD(ipa_config_lwm2m_t, port);
  FIELD(ipa_config_lwm2m_t, dtls);
  FIELD(ipa_config_lwm2m_t, bootstrap);
  FIELD(ipa_config_lwm2m_t, ipv4);
  FIELD(ipa_config_lwm2m_t, client_name);

  TYPE(ipa_config_http_t);
  FIELD(ipa_config_http_t, fqdn);
  FIELD(ipa_config_http_t, max_time_without_transmission);
  FIELD(ipa_config_http_t, http_timeout);
  FIELD(ipa_config_http_t, sync_sleep_time);

  TYPE(ipa_task_callbacks_t);
  FIELD(ipa_task_callbacks_t, task_start_cb);
  FIELD(ipa_task_callbacks_t, task_end_cb);

  TYPE(ipa_pkid_t);
  FIELD(ipa_pkid_t, pkid);
  FIELD(ipa_pkid_t, pkid_size);
  TYPE(ipa_pkid_list_t);
  FIELD(ipa_pkid_list_t, items);
  FIELD(ipa_pkid_list_t, count);
  TYPE(ipa_euicc_info1_t);
  FIELD(ipa_euicc_info1_t, raw);
  FIELD(ipa_euicc_info1_t, raw_size);
  FIELD(ipa_euicc_info1_t, svn);
  FIELD(ipa_euicc_info1_t, svn_size);
  FIELD(ipa_euicc_info1_t, svn_present);
  FIELD(ipa_euicc_info1_t, ci_pkid_list_for_verification);
  FIELD(ipa_euicc_info1_t, verification_list_present);
  FIELD(ipa_euicc_info1_t, ci_pkid_list_for_signing);
  FIELD(ipa_euicc_info1_t, signing_list_present);
  TYPE(ipa_euicc_info2_t);
  FIELD(ipa_euicc_info2_t, profile_version);
  FIELD(ipa_euicc_info2_t, ext_card_res_info);
  FIELD(ipa_euicc_info2_t, uicc_capability_mask);
  FIELD(ipa_euicc_info2_t, rsp_capability_mask);
  FIELD(ipa_euicc_info2_t, ipa_pkid_list_data);
  FIELD(ipa_euicc_info2_t, euicc_category);
  FIELD(ipa_euicc_info2_t, forbidden_pprs);

  TYPE(profile_info_t);
  FIELD(profile_info_t, iccid);
  FIELD(profile_info_t, isdp_aid);
  FIELD(profile_info_t, profile_state);
  FIELD(profile_info_t, profile_nickname);
  FIELD(profile_info_t, icon);
  FIELD(profile_info_t, notification_configuration_info);
  FIELD(profile_info_t, profile_owner);
  FIELD(profile_info_t, profile_policy_rules);
  FIELD(profile_info_t, field_is_present);

  TYPE(eim_configuration_data_t);
  FIELD(eim_configuration_data_t, eim_id);
  FIELD(eim_configuration_data_t, eim_id_len);
  FIELD(eim_configuration_data_t, eim_fqdn);
  FIELD(eim_configuration_data_t, eim_id_type);
  FIELD(eim_configuration_data_t, eim_public_key_data);
  FIELD(eim_configuration_data_t, trusted_public_key_data_tls);
  FIELD(eim_configuration_data_t, eim_supported_protocol);
  FIELD(eim_configuration_data_t, field_is_present);

  TYPE(notification_group_node_t);
  FIELD(notification_group_node_t, notification_address);
  FIELD(notification_group_node_t, sequence_number_list);
  FIELD(notification_group_node_t, sequence_number_list_size);
  FIELD(notification_group_node_t, next);
  TYPE(euicc_memory_reset_request_t);
  TYPE(eim_config_t);
  TYPE(profile_enabling_config_t);
  TYPE(set_default_dp_address_request_t);

  ENUM(eOk);
  ENUM(eFatal);
  ENUM(eNotSupported);
  ENUM(eNotImpl);
  ENUM(eBadArg);
  ENUM(eJsonParseError);
  ENUM(eSessionCancelled);
  ENUM(eNotEnoughBuffer);
  ENUM(eNoData);
  ENUM(eNoMem);
  ENUM(eSimBusy);
  ENUM(eInvalidFormat);
  ENUM(IPA_EVENT_PROVISIONING_NEEDED);
  ENUM(IPA_EVENT_INITIALIZATION_SUCCESS);
  ENUM(IPA_EVENT_INITIALIZATION_FAILED);
  ENUM(IPA_EVENT_SERVICE_CONNECT_SUCCESS);
  ENUM(ES10_DRIVER_AT);
  ENUM(ES10_DRIVER_NONE);
  ENUM(PROFILE_STATE_DISABLED);
  ENUM(PROFILE_STATE_ENABLED);
  ENUM(PROFILE_ROLLBACK_RESULT_OK);
  ENUM(PROFILE_ROLLBACK_RESULT_UNDEFINED_ERROR);

  printf("}\n");
  return 0;
}
