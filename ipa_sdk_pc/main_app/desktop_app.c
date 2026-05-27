#include "ipa.h"
#include "ipa_core.h"
#include "ipa_local.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void app_notify_task_start(uint32_t task_id) {
  printf("desktop_app: Task %u started for the HTTP EIM connection.\n",
         task_id);
}

void app_notify_task_end(uint32_t task_id) {
  printf("desktop_app: Task %u ended for the HTTP EIM connection. App can "
         "sleep now.\n",
         task_id);
}

void main_app_event_callback(ipa_event_type_t const event_type,
                             void *event_data) {
  if (event_type == IPA_EVENT_INITIALIZATION_SUCCESS) {
    printf("==> IPA Event: IPA_EVENT_INITIALIZATION_SUCCESS.\n");
  } else if (event_type == IPA_EVENT_PROVISIONING_NEEDED) {
    printf("==> IPA Event: IPA_EVENT_PROVISIONING_NEEDED.\n");
  } else if (event_type == IPA_EVENT_SERVICE_CONNECT_SUCCESS) {
    printf("==> IPA Event: IPA_EVENT_SERVICE_CONNECT_SUCCESS.\n");
  } else if (event_type == IPA_EVENT_INITIALIZATION_FAILED) {
    printf("==> IPA Event: IPA_EVENT_INITIALIZATION_FAILED.\n");
  }
}

int do_Ipa_init_library() {
  cl_config_t config = {0};
  config.es10_driver_selected = ES10_DRIVER_AT;
  config.driver_id = "/dev/ttyUSB2";
  config.log_level = eLogDebug;
  config.initial_refresh_sleep = 10;
  config.refresh_max_sleep = 3600;
  config.esipa_sync_package_retrieval_time = 300;

  if (ipa_init_library(&config, main_app_event_callback) != 0) {
    fprintf(stderr, "main: IPA library initialization failed. Exiting.\n");
    return -1;
  }
  return 0;
}

void print_hex_bytes(const uint8_t *data, size_t size) {
  for (size_t i = 0; i < size; i++) {
    printf("%02X", data[i]);
  }
}

void print_euicc_info1_data(const ipa_euicc_info1_t *data) {
  if (!data)
    return;
  printf("  Printing parsed euiccInfo1 data:\n");

  printf("    - Raw TLV Size: %u bytes\n", data->raw_size);

  if (data->svn_present) {
    printf("    - SVN: ");
    print_hex_bytes(data->svn, data->svn_size);
    printf("\n");
  } else {
    printf("    - SVN: Not Present\n");
  }

  if (data->verification_list_present) {
    printf("    - CI PKID List for Verification (%u):\n",
           data->ci_pkid_list_for_verification.count);
    for (uint32_t i = 0; i < data->ci_pkid_list_for_verification.count; i++) {
      printf("      - [%u]: ", i + 1);
      print_hex_bytes(data->ci_pkid_list_for_verification.items[i].pkid,
                      data->ci_pkid_list_for_verification.items[i].pkid_size);
      printf("\n");
    }
  } else {
    printf("    - CI PKID List for Verification: Not Present\n");
  }

  if (data->signing_list_present) {
    printf("    - CI PKID List for Signing (%u):\n",
           data->ci_pkid_list_for_signing.count);
    for (uint32_t i = 0; i < data->ci_pkid_list_for_signing.count; i++) {
      printf("      - [%u]: ", i + 1);
      print_hex_bytes(data->ci_pkid_list_for_signing.items[i].pkid,
                      data->ci_pkid_list_for_signing.items[i].pkid_size);
      printf("\n");
    }
  } else {
    printf("    - CI PKID List for Signing: Not Present\n");
  }
}

void print_euicc_info2_data(const ipa_euicc_info2_t *data) {
  if (!data)
    return;
  printf("  -> Printing parsed euiccInfo2 data:\n");

  if (data->profile_version)
    printf("    - profileVersion: %s\n", data->profile_version);
  if (data->svn)
    printf("    - svn: %s\n", data->svn);
  if (data->euicc_firmware_ver)
    printf("    - euiccFirmwareVer: %s\n", data->euicc_firmware_ver);

  printf("    - extCardResource:\n");
  printf("      - installedAppNumber: %d\n",
         data->ext_card_res_info.installed_app_number);
  printf("      - freeNonVolatileMem: %d\n",
         data->ext_card_res_info.free_non_volatile_mem);
  printf("      - freeVolatileMem: %d\n",
         data->ext_card_res_info.free_volatile_mem);

  printf("      - uicc_capability_mask: ");
  for (int i = 0; i < 32; i++) {
    printf("%d ", data->uicc_capability_mask[i]);
  }
  printf("\n");

  // 打印 rsp_capability_mask[16]
  printf("      - rsp_capability_mask: ");
  for (int i = 0; i < 16; i++) {
    printf("%d ", data->rsp_capability_mask[i]);
  }
  printf("\n");

  if (data->euicc_category_present)
    printf("    - euiccCategory: %d\n", data->euicc_category);

  if (data->forbidden_pprs_present)
    printf("    - forbiddenProfilePolicyRules: Present\n");

  if (data->pp_version)
    printf("    - ppVersion: %s\n", data->pp_version);
  if (data->sas_acreditation_number)
    printf("    - sasAcreditationNumber: %s\n", data->sas_acreditation_number);

  if (data->ipa_pkid_list_data.ci_pkid_list_for_verification.count > 0) {
    printf("    - euiccCiPKIdListForVerification (%u):\n",
           data->ipa_pkid_list_data.ci_pkid_list_for_verification.count);
    for (uint32_t i = 0;
         i < data->ipa_pkid_list_data.ci_pkid_list_for_verification.count;
         i++) {
      printf("      - ");
      print_hex_bytes(
          data->ipa_pkid_list_data.ci_pkid_list_for_verification.items[i].pkid,
          data->ipa_pkid_list_data.ci_pkid_list_for_verification.items[i]
              .pkid_size);
      printf("\n");
    }
  }

  if (data->ipa_pkid_list_data.ci_pkid_list_for_signing.count > 0) {
    printf("    - euiccCiPKIdListForSigning (%u):\n",
           data->ipa_pkid_list_data.ci_pkid_list_for_signing.count);
    for (uint32_t i = 0;
         i < data->ipa_pkid_list_data.ci_pkid_list_for_signing.count; i++) {
      printf("      - ");
      print_hex_bytes(
          data->ipa_pkid_list_data.ci_pkid_list_for_signing.items[i].pkid,
          data->ipa_pkid_list_data.ci_pkid_list_for_signing.items[i].pkid_size);
      printf("\n");
    }
  }

  if (data->javacard_version)
    printf("    - javacardVersion: %s\n", data->javacard_version);
  if (data->globalplatform_version)
    printf("    - globalplatformVersion: %s\n", data->globalplatform_version);
}

void do_get_eid() {
  printf("Calling ipa__get_eid_cstring()...\n");
  char eid_str[33] = {0};
  if (ipa__get_eid_cstring(eid_str, sizeof(eid_str)) == eOk) {
    printf("  -> Success! EID: %s\n", eid_str);
  } else {
    printf("  -> Error!\n");
  }
}

void do_get_euicc_info1() {
  printf("Calling ipa__get_euicc_info_1()...\n");

  ipa_euicc_info1_t data = {0};
  if (ipa__get_euicc_info_1(&data) == eOk) {
    print_euicc_info1_data(&data);
    ipa__free_euicc_info1_data(&data);
  } else {
    printf("  -> Error!\n");
  }
}

void do_get_euicc_info2() {
  printf("Calling ipa__get_euicc_info_2()...\n");

  ipa_euicc_info2_t data = {0};

  if (ipa__get_euicc_info_2(&data) == eOk) {
    printf("ipa__get_euicc_info_2  -> Success!\n");
    print_euicc_info2_data(&data);
    ipa__free_euicc_info2_data(&data);
  } else {
    printf("  -> Error!\n");
  }
}

void print_all_profiles(const profile_info_t *profiles, uint32_t num_profiles) {
  printf("Total Profiles: %u\n", num_profiles);

  if (profiles) {
    for (uint32_t i = 0; i < num_profiles; i++) {
      const profile_info_t *p = &profiles[i];
      printf("  [%u] ------------------------------------------------\n",
             i + 1);

      printf("    ICCID: ");
      if (p->field_is_present.iccid) {
        print_hex_bytes(p->iccid.value, sizeof(p->iccid.value));
      } else {
        printf("N/A");
      }
      printf("\n");

      printf("    ISDP AID: ");
      if (p->field_is_present.isdp_aid) {
        print_hex_bytes((const uint8_t *)&p->isdp_aid, 16);
      } else {
        printf("N/A");
      }
      printf("\n");

      printf("    Name: ");
      if (profiles[i].field_is_present.profile_name) {
        printf("%.*s", p->profile_name.len, p->profile_name.value);
      } else {
        printf("N/A");
      }
      printf("\n");

      printf("    State: %s\n",
             p->field_is_present.profile_state
                 ? (p->profile_state == PROFILE_STATE_ENABLED ? "ENABLED"
                                                              : "DISABLED")
                 : "N/A");

      printf("    Provider: ");
      if (profiles[i].field_is_present.service_provider_name) {
        printf("%.*s", p->service_provider_name.len,
               p->service_provider_name.value);
      } else {
        printf("N/A");
      }
      printf("\n");

      printf("    Nickname: ");
      if (p->field_is_present.profile_nickname) {
        printf("%.*s", p->profile_nickname.len, p->profile_nickname.value);
      } else {
        printf("N/A");
      }
      printf("\n");

      printf("    Icon Type: ");
      if (p->field_is_present.icon_type) {
        printf("%s", p->icon_type == ICON_TYPE_PNG ? "PNG" : "JPG");
      } else {
        printf("N/A");
      }
      printf("\n");

      printf("    Class: ");
      if (p->field_is_present.profile_class) {
        switch (p->profile_class) {
        case PROFILE_CLASS_TEST:
          printf("TEST");
          break;
        case PROFILE_CLASS_PROVISIONING:
          printf("PROVISIONING");
          break;
        case PROFILE_CLASS_OPERATIONAL:
          printf("OPERATIONAL");
          break;
        default:
          printf("UNKNOWN (%d)", p->profile_class);
          break;
        }
      } else {
        printf("N/A");
      }
      printf("\n");

      printf("    Owner (MCC/MNC): ");
      if (p->field_is_present.profile_owner) {
        print_hex_bytes(p->profile_owner.mcc_mnc.value, 3);
        if (p->profile_owner.field_is_present.gid1) {
          printf(", GID1: ");
          print_hex_bytes(p->profile_owner.gid1, p->profile_owner.gid1_size);
        }
        if (p->profile_owner.field_is_present.gid2) {
          printf(", GID2: ");
          print_hex_bytes(p->profile_owner.gid2, p->profile_owner.gid2_size);
        }
      } else {
        printf("N/A");
      }
      printf("\n");

      printf("    Policy Rules: ");
      if (p->field_is_present.profile_policy_rules) {
        printf("Update: %d, PPR1: %d, PPR2: %d",
               p->profile_policy_rules.ppr_update_control,
               p->profile_policy_rules.ppr1, p->profile_policy_rules.ppr2);
      } else {
        printf("N/A");
      }
      printf("\n");

      if (p->field_is_present.dp_propietary_data) {
        printf("    DP Proprietary Data (OID): ");
        print_hex_bytes(p->dp_propietary_data.dp_oid,
                        p->dp_propietary_data.dp_oid_size);
        printf("\n");
      }
    }
  } else {
    printf("  No profiles data available.\n");
  }
}

void do_get_all_profiles() {
    printf("\n-> Calling ipa__get_all_profiles_info()...\n");
    profile_info_t* profiles = NULL;
    uint32_t num_profiles = 0;
    uint8_t* raw_tlv = NULL;
    if (ipa__get_all_profiles_info(&profiles, &num_profiles, &raw_tlv) == eOk) {
        print_all_profiles(profiles, num_profiles);
        printf("do_get_all_profiles  -> Success! Found %u profiles.\n", num_profiles);
        free(profiles);
        free(raw_tlv);
    } else {
        printf("do_get_all_profiles  -> Error!\n");
    }
}

void do_get_certs() {
  printf("\n-> Calling ipa__get_certs()...\n");
  ipa_pkid_list_data_t data = {0};
  if (ipa__get_certs(&data) == eOk) {
    printf("do_get_certs  -> Success!\n");
    if (data.ci_pkid_list_for_verification.count > 0) {
      printf("    - euiccCiPKIdListForVerification (%u):\n",
             data.ci_pkid_list_for_verification.count);
      for (uint32_t i = 0; i < data.ci_pkid_list_for_verification.count; i++) {
        printf("      - ");
        print_hex_bytes(data.ci_pkid_list_for_verification.items[i].pkid,
                        data.ci_pkid_list_for_verification.items[i].pkid_size);
        printf("\n");
      }
    }

    if (data.ci_pkid_list_for_signing.count > 0) {
      printf("    - euiccCiPKIdListForSigning (%u):\n",data.ci_pkid_list_for_signing.count);
      for (uint32_t i = 0; i < data.ci_pkid_list_for_signing.count; i++) {
        printf("      - ");
        print_hex_bytes(data.ci_pkid_list_for_signing.items[i].pkid,
                data.ci_pkid_list_for_signing.items[i].pkid_size);
        printf("\n");
      }
    }
    ipa__free_certs_data(&data);
  } else {
    printf("do_get_certs  -> Error!\n");
  }
}

void do_get_eim_configs() {
  printf("\n-> Calling ipa__get_eim_configurations()...\n");
  eim_configuration_data_t cfg = {0};
  uint8_t *response_tlv = NULL;
  if (ipa__get_eim_configuration(&cfg, &response_tlv) == eOk) {
    printf("    eIM ID: ");
    if (cfg.eim_id && cfg.eim_id_len > 0) {
      printf("%.*s", cfg.eim_id_len, (char *)cfg.eim_id);
    } else {
      printf("N/A");
    }
    printf("\n");

    if (cfg.field_is_present.eim_fqdn) {
      printf("    eIM FQDN: %.*s\n", cfg.eim_fqdn_len, (char *)cfg.eim_fqdn);
    }

    if (cfg.field_is_present.eim_id_type) {
      printf("    eIM ID Type: ");
      switch (cfg.eim_id_type) {
      case EIM_ID_TYPE_OID:
        printf("OID");
        break;
      case EIM_ID_TYPE_FQDN:
        printf("FQDN");
        break;
      case EIM_ID_TYPE_PROPIETARY:
        printf("PROPRIETARY");
        break;
      default:
        printf("Unknown (%d)", cfg.eim_id_type);
      }
      printf("\n");
    }

    if (cfg.field_is_present.counter_value) {
      printf("    Counter Value: %u\n", cfg.counter_value);
    }

    if (cfg.field_is_present.association_token) {
      printf("    Association Token: %u\n", cfg.association_token);
    }

    if (cfg.field_is_present.eim_public_key_data) {
      printf("    eIM Public Key Data:\n");
      printf("      Choice: %s\n",
             cfg.eim_public_key_data.choice == EIM_PUBLIC_KEY_CHOICE
                 ? "Public Key"
                 : "Certificate");
      printf("      Value: ");
      print_hex_bytes(cfg.eim_public_key_data.value,
                      cfg.eim_public_key_data.value_size);
      printf("\n");
    }

    if (cfg.field_is_present.trusted_public_key_data_tls) {
      printf("    Trusted Public Key Data TLS:\n");
      printf("      Choice: %s\n",
             cfg.trusted_public_key_data_tls.choice == TRUSTED_EIM_PK_TLS_CHOICE
                 ? "Public Key"
                 : "Certificate");
      printf("      Value: ");
      print_hex_bytes(cfg.trusted_public_key_data_tls.value,
                      cfg.trusted_public_key_data_tls.value_size);
      printf("\n");
    }

    if (cfg.field_is_present.eim_supported_protocol) {
      printf("    Supported Protocols:\n");
      printf("      Retrieve HTTPS: %s\n",
             cfg.eim_supported_protocol.eim_retrieve_https ? "Yes" : "No");
      printf("      Retrieve CoAPS: %s\n",
             cfg.eim_supported_protocol.eim_retrieve_coaps ? "Yes" : "No");
      printf("      Inject HTTPS: %s\n",
             cfg.eim_supported_protocol.eim_inject_https ? "Yes" : "No");
      printf("      Inject CoAPS: %s\n",
             cfg.eim_supported_protocol.eim_inject_coaps ? "Yes" : "No");
      printf("      Proprietary: %s\n",
             cfg.eim_supported_protocol.eim_proprietary ? "Yes" : "No");
    }

    if (cfg.field_is_present.euicc_ci_pk_id) {
      printf("    eUICC CI PK ID: Present\n");
    }

    if (cfg.field_is_present.indirect_profile_download) {
      printf("    Indirect Profile Download: Supported\n");
    }
    if (response_tlv) {
      free(response_tlv);
    }
  } else {
    printf("  -> Error!\n");
  }
}

void do_set_default_dp() {
  printf("\n-> Calling ipa_local_commands__set_default_dp_address()...\n");
  set_default_dp_address_request_t request = {0};
  request.default_dp_address =
      (unsigned char *)"sm-v4-080-b-gtm.pr.go-esim.com";
  request.default_dp_address_len = strlen((char *)request.default_dp_address);
  if (ipa_local__set_default_dp_address(&request) == eOk) {
    printf(" set_default_dp -> Success!\n");
  } else {
    printf(" set_default_dp -> Error!\n");
  }
}

void do_add_initial_eim() {
  eim_config_t eim_config_t = {
      .eim_id = "1.3.6.1.4.1.11791.104.6.1.1.1.2",
      .eim_fqdn = "https.prp.eim.gdiotsuite.com",
      .eim_public_key_base64 =
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIgmSMj+RJU9+1SejDYK7e+"
          "aP1SWdkSLL7G+FRZriNPw/UAfl8ZHlh/CGZIRJqHKta9q806SPkve8WjFlgmWoYg==",
      .eim_id_type = EIM_ID_TYPE_OID,
      .counter_value = 0,
      .eim_supported_protocol.eim_retrieve_https = true,
      .eim_supported_protocol.eim_inject_https = false,
      .eim_supported_protocol.eim_retrieve_coaps = false,
      .eim_supported_protocol.eim_inject_coaps = false,
      .eim_supported_protocol.eim_proprietary = true,
      .indirect_profile_download = true,
      .choice = EIM_PUBLIC_KEY_CHOICE};

  printf("\n-> Calling ipa_local__add_initial_eim()...\n");

  if (ipa_local__add_initial_eim(&eim_config_t) == eOk) {
    printf(" do_add_initial_eim -> Success!\n");
  } else {
    printf("do_add_initial_eim  -> Error!\n");
  }
}

void do_profile_rollback() {
  printf("\n-> Calling ipa__execute_profile_rollback_result()...\n");
  profile_rollback_result_t result = {0};
  if (ipa__execute_profile_rollback_result(&result) == eOk) {
    printf("  -> Success! Result choice: %d\n", result);
  } else {
    printf("  -> Error!\n");
  }
}

void do_memory_reset() {
  printf("\n-> Calling ipa_local__euicc_memory_reset()...\n");
  euicc_memory_reset_request_t request = {0};
  request.reset_default_smdp_address = true;
  request.reset_eim_config_data = true;
  request.delete_preloaded_test_profiles = true;
  request.delete_operational_profiles = true;
  if (ipa_local__euicc_memory_reset(&request) == eOk) {
    printf("do_memory_reset  -> Success!\n");
  } else {
    printf("do_memory_reset  -> Error!\n");
  }
}

void do_exec_fallback() {
  printf("\n-> Calling ipa__execute_fallback_mechanism()...\n");
  if (ipa__execute_fallback_mechanism() == eOk) {
    printf("do_exec_fallback  -> Success!\n");
  } else {
    printf("do_exec_fallback  -> Error!\n");
  }
}

void do_return_from_fallback() {
  printf("\n-> Calling ipa__return_from_fallback()...\n");
  if (ipa__return_from_fallback() == eOk) {
    printf("do_return_from_fallback  -> Success!\n");
  } else {
    printf("do_return_from_fallback  -> Error!\n");
  }
}

void do_configure_immediate_profile_enabling() {
  printf("\n-> Calling "
         "ipa_local__configure_immediate_profile_enabling()...\n");

  profile_enabling_config_t request = {0};
  request.immediate_enable_flag = true;
  const char *smdp_address = "sm-v4-080-b-gtm.pr.go-esim.com";
  request.smdp_address = (char *)smdp_address;
  const char *smdp_oid = "1.3.6.1.4.1.11791.104.2.71.1";
  request.smdp_oid = (char *)smdp_oid;

  ErrCode rc = ipa_local__configure_immediate_profile_enabling(&request);

  if (rc == eOk) {
    printf("  -> Success! Configuration command executed.\n");
  } else {
    printf("  -> Error! Command failed with code: %d\n", rc);
  }
}

void do_connect_mqtt_service() {
  ipa_config_mqtt_t *mqtt_config = malloc(sizeof(ipa_config_mqtt_t));
  *mqtt_config = (ipa_config_mqtt_t){
      .protocol = "ssl",
      .hostname = "mqtt.prp.eim.gdiotsuite.com",
      .port = 8883,
      .tls_config = {
          .server_cert_absolute_pem_path =
              "/mnt/c/Users/zhshuang/Desktop/certificates/"
              "mtls_mqtt_server_cer.pem",
          .client_cert_absolute_pem_path = "/mnt/c/Users/zhshuang/Desktop/"
                                           "certificates/mtls_mqtt_cli_cer.pem",
          .private_key_absolute_pem_path =
              "/mnt/c/Users/zhshuang/Desktop/certificates/mtls_mqtt_pk.pem"}};

  connect_mqtt_service(mqtt_config);
}

void do_connect_lwm2m_service() {
  ipa_config_lwm2m_t *lwm2m_config = malloc(sizeof(ipa_config_lwm2m_t));
  *lwm2m_config = (ipa_config_lwm2m_t){
      .hostname = "lwm2m.my-iot-platform.com",
      .port = 5684,
      .dtls = true,
      .bootstrap = false,
      .ipv4 = true,
      .client_name = "urn:imei:123456789012345",

  };
  connect_lwm2m_service(lwm2m_config);
}

void do_connect_http_service() {
  ipa_task_callbacks_t task_callbacks = {
      .task_start_cb = app_notify_task_start,
      .task_end_cb = app_notify_task_end,
  };
  // 设置http 轮训任务开始和结束回调函数
  ipa_register_task_callbacks(&task_callbacks);

  ipa_config_http_t *http_config = malloc(sizeof(ipa_config_http_t));
  *http_config = (ipa_config_http_t){
      .fqdn = "https.prp.eim.gdiotsuite.com",
      .max_time_without_transmission = 5,
      .http_timeout = 10,    // 设置http访问超时时间10秒
      .sync_sleep_time = 60, // 设置每次轮训休眠间隔60秒
  };
  connect_http_service(http_config);
}

void do_disconnect_eim_service() {
  printf("\n-> Stopping ALL services (HTTP, MQTT, LwM2M)...\n");
  stop_eim_service();
}

void ipa_profile_state_change_callback(const profile_info_t *profiles,
                                       uint32_t num_profiles) {
  printf("\n*** [Callback] Profile State Changed ***\n");
  print_all_profiles(profiles, num_profiles);
  printf("****************************************\n");
}

void do_ipa__register_profile_state_callback() {
  ipa__register_profile_state_callback(ipa_profile_state_change_callback);
}

void show_menu() {
  printf("\n=========== IPA Application Menu ===========\n");
  printf("--- Queries ---\n");
  printf(" 1. Get EID (string)\n");
  printf(" 2. Get eUICC Info 1\n");
  printf(" 3. Get eUICC Info 2\n");
  printf(" 4. Get All Profiles\n");
  printf(" 5. Get Certs\n");
  printf(" 6. Get eIM Configurations\n");
  printf("--- Commands ---\n");
  printf(" 7. Set Default DP Address\n");
  printf(" 8. Add Initial eIM\n");
  printf(" 9. Execute Profile Rollback\n");
  printf("10. eUICC Memory Reset\n");
  printf("11. Execute Fallback Mechanism\n");
  printf("12. Return from Fallback\n");
  printf("13. Configure Immediate Profile Enabling\n");
  printf("14. Enable emergency profile\n");
  printf("15. Disable emergency profile\n");
  printf("16. Retrieve notifications list\n");
  printf("17. Delivery all notifications\n");
  printf("18. Delivery single notification\n");
  printf("19. Remove notification\n");
  printf("20. Remove all notifications\n");
  printf("--- Services ---\n");
  printf("21. Connect MQTT Service\n");
  printf("22. Connect LwM2M Service\n");
  printf("23. Connect HTTP Service\n");
  printf("24. Disconnect EIM Services\n");
  printf("25. Register Profile State Callback\n");
  printf("--- Control ---\n");
  printf("26. Init IPA Library\n");
  printf("27. Deinit IPA Library\n");
  printf("99. Exit\n");
  printf("==========================================\n");
  printf("Please enter your choice: ");
}

void do_ipa__enable_emergency_profile() {
  int err;
  if ((err = ipa__enable_emergency_profile()) != eOk) {
    printf("Enable emergency profile failed, error code: %d\n", err);
  } else {
    printf("  ->  Enable emergency profile success!\n");
  }
}

void do_ipa__disable_emergency_profile() {
  int err;
  if ((err = ipa__disable_emergency_profile()) != eOk) {
    printf("Disable emergency profile failed, error code: %d\n", err);
  } else {
    printf("  ->  Disable emergency profile success!\n");
  }
}

static char *g_notification_address_fqdn;
static uint32_t g_sequence_number;

void print_notification_list(notification_group_node_t *head) {
  notification_group_node_t *current = head;
  int node_count = 0;

  printf("========== Notification Group List ==========\n");

  while (current != NULL) {
    printf("Node %d:\n", node_count++);
    printf("  Notification Address: %s\n", current->notification_address.fqdn);
    g_notification_address_fqdn = current->notification_address.fqdn;
    // 打印序列号列表
    printf("  Sequence Numbers: [");
    for (size_t i = 0; i < current->sequence_number_list_size; i++) {
      printf("%u", current->sequence_number_list[i]);
      g_sequence_number = current->sequence_number_list[i];
      if (i < current->sequence_number_list_size - 1) {
        printf(", ");
      }
    }
    printf("]\n");
    printf("  Sequence Count: %zu\n", current->sequence_number_list_size);
    printf("  Next: %p\n", (void *)current->next);
    printf("------------------------\n");

    current = current->next;
  }

  if (node_count == 0) {
    printf("List is empty\n");
  } else {
    printf("Total nodes: %d\n", node_count);
  }
  printf("============================================\n");
}

void do_ipa__notifications_delivery__initialize_notifications_group_list(void) {
  int err;
  notification_group_node_t *notifications_list = NULL;

  if ((err = ipa__notifications_delivery__initialize_notifications_group_list(
           &notifications_list)) != eOk) {
    printf("Initialize notifications group list failed, error code: %d\n", err);
  } else {
    printf("  ->  Initialize notifications group list success!\n");
    print_notification_list(notifications_list);
   //ipa__notifications_delivery__free_notification_list(&notifications_list); 为了方便测试其他通知相关函数，所以注掉了。
  }
}

void do_ipa__notifications_delivery__all_notifications() {
  int err;

  if ((err = ipa__notifications_delivery__all_notifications()) != eOk) {
    printf("Get all notifications failed, error code: %d\n", err);
  } else {
    printf("  ->  Get all notifications success!\n");
  }
}

void do_ipa__notifications_delivery__seq_number_single_notification_delivery(
    void) {
  int err;
  bool remove_after_send = false;
  const char *smdp_address = g_notification_address_fqdn;
  uint32_t seq_number = g_sequence_number;

  if ((err =
           ipa__notifications_delivery__seq_number_single_notification_delivery(
               remove_after_send, smdp_address, seq_number)) != eOk) {
    printf(
        "Single notification delivery by seq number failed, error code: %d\n",
        err);
  } else {
    printf("  ->  Single notification delivery success!\n");
  }
}

void do_ipa__notifications_delivery__remove_notification(void) {
  int err;

  if ((err = ipa__notifications_delivery__remove_notification(
           g_sequence_number)) != eOk) {
    printf("Remove notification by seq number failed, error code: %d\n", err);
  } else {
    printf("  ->  Remove notification success!\n");
  }
}

void do_ipa__notifications_delivery__remove_all_notification(void) {
  int err;

  if ((err = ipa__notifications_delivery__remove_all_notifications()) != eOk) {
    printf("Remove all notifications failed, error code: %d\n", err);
  } else {
    printf("  ->  Remove all notifications success!\n");
  }
}

int main(void) {
  int choice = 0;

  while (choice != 99) {
    show_menu();
    if (scanf("%d", &choice) != 1) {
      while (getchar() != '\n')
        printf("Invalid input. Please enter a number.\n");
      continue;
    }
    switch (choice) {
    case 0:
      show_menu();
      break;
    case 1:
      do_get_eid();
      break;
    case 2:
      do_get_euicc_info1();
      break;
    case 3:
      do_get_euicc_info2();
      break;
    case 4:
      do_get_all_profiles();
      break;
    case 5:
      do_get_certs();
      break;
    case 6:
      do_get_eim_configs();
      break;
    case 7:
      do_set_default_dp();
      break;
    case 8:
      do_add_initial_eim();
      break;
    case 9:
      do_profile_rollback();
      break;
    case 10:
      do_memory_reset();
      break;
    case 11:
      do_exec_fallback();
      break;
    case 12:
      do_return_from_fallback();
      break;
    case 13:
      do_configure_immediate_profile_enabling();
      break;
    case 14:
      do_ipa__enable_emergency_profile();
      break;
    case 15:
      do_ipa__disable_emergency_profile();
      break;
    case 16:
      do_ipa__notifications_delivery__initialize_notifications_group_list();
      break;
    case 17:
      do_ipa__notifications_delivery__all_notifications();
      break;
    case 18:
      do_ipa__notifications_delivery__seq_number_single_notification_delivery();
      break;
    case 19:
      do_ipa__notifications_delivery__remove_notification();
      break;
    case 20:
      do_ipa__notifications_delivery__remove_all_notification();
      break;
    case 21:
      do_connect_mqtt_service();
      break;
    case 22:
      do_connect_lwm2m_service();
      break;
    case 23:
      do_connect_http_service();
      break;
    case 24:
      do_disconnect_eim_service();
      break;
    case 25:
      do_ipa__register_profile_state_callback();
      break;
    case 26:
      do_Ipa_init_library();
      break;
    case 27:
      ipa_deinit_library();
      break;
    case 99:
      printf("\nExiting application...\n");
      break;
    default:
      printf("\nInvalid choice. Please try again.\n");
      break;
    }
  }
  return 0;
}
