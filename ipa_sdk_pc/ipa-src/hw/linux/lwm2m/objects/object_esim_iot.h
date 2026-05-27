/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#ifdef ENABLE_LWM2M
#include "lwm2m_client.h"
#include "ipa_typedefs.h"
#include "liblwm2m.h"

#define ESIM_IOT_OBJECT_ID 3443

lwm2m_object_t * get_esim_iot_object(lwm2m_esim_iot_callbacks_t* callbacks, void* context);
void free_esim_iot_object(lwm2m_object_t * object);
#endif
