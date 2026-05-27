/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#ifdef LWM2M_VERSION_1_0
#error "LwM2M can only be supported in the IPA with version 1.1 or higher"
#endif
#ifdef ENABLE_LWM2M
#include "lwm2m_client.h"
#include "liblwm2m.h"
#ifdef WITH_TINYDTLS
#include "dtlsconnection.h"
#else
#include "connection.h"
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "object_security.h"
#include "object_server.h"
#include "object_device.h"
#include "object_esim_iot.h"
#include "memory_manager.h"
#include "log.h"

#define MAX_PACKET_SIZE 2048
#define DEFAULT_SERVER_IPV6 "[::1]"
#define DEFAULT_SERVER_IPV4 "127.0.0.1"

#define LOCAL_CLIENT_PORT "56830"
#define COAP_URI_TEMPLATE "coap://%s:%d"

#define OBJ_COUNT 4
lwm2m_object_t * lwm2m_client_objects[OBJ_COUNT];

// only backup security and server objects
# define BACKUP_OBJECT_COUNT 2
lwm2m_object_t * backupObjectArray[BACKUP_OBJECT_COUNT];

typedef struct
{
    lwm2m_object_t * securityObjP;
    lwm2m_object_t * serverObject;
    int sock;
    lwm2m_context_t * lwm2mH;
    int addressFamily;
#ifdef WITH_TINYDTLS
    dtls_connection_t * connList;
#else
    connection_t * connList;
#endif
#ifdef LWM2M_BOOTSTRAP
    lwm2m_client_state_t previousState;
#endif
} client_data_t;



#ifdef WITH_TINYDTLS
void * lwm2m_connect_server(uint16_t secObjInstID,
                            void * userData)
{
  client_data_t * dataP;
  lwm2m_list_t * instance;
  dtls_connection_t * newConnP = NULL;
  dataP = (client_data_t *)userData;
  lwm2m_object_t  * securityObj = dataP->securityObjP;

  instance = LWM2M_LIST_FIND(dataP->securityObjP->instanceList, secObjInstID);
  if (instance == NULL) return NULL;


  newConnP = connection_create(dataP->connList, dataP->sock, securityObj, instance->id, dataP->lwm2mH, dataP->addressFamily);
  if (newConnP == NULL)
  {
      LOGE"Connection creation failed.");
      return NULL;
  }

  dataP->connList = newConnP;
  return (void *)newConnP;
}
#else
void * lwm2m_connect_server(uint16_t secObjInstID,
                            void * userData)
{
    client_data_t * dataP;
    char * uri;
    char * host;
    char * port;
    connection_t * newConnP = NULL;

    dataP = (client_data_t *)userData;

    uri = get_server_uri(dataP->securityObjP, secObjInstID);

    if (uri == NULL) return NULL;

    // parse uri in the form "coaps://[host]:[port]"
    if (0==strncmp(uri, "coaps://", strlen("coaps://"))) {
        host = uri+strlen("coaps://");
    }
    else if (0==strncmp(uri, "coap://",  strlen("coap://"))) {
        host = uri+strlen("coap://");
    }
    else {
        goto exit;
    }
    port = strrchr(host, ':');
    if (port == NULL) goto exit;
    // remove brackets
    if (host[0] == '[')
    {
        host++;
        if (*(port - 1) == ']')
        {
            *(port - 1) = 0;
        }
        else goto exit;
    }
    // split strings
    *port = 0;
    port++;

    LOGI("[LwM2M]\tOpening connection to server at %s:%s", host, port);
    newConnP = connection_create(dataP->connList, dataP->sock, host, port, dataP->addressFamily);
    if (newConnP == NULL) {
        LOGE("[lwm2m_connect_server] Connection creation failed.");
    }
    else {
        dataP->connList = newConnP;
    }

exit:
    lwm2m_free(uri);
    return (void *)newConnP;
}
#endif

void lwm2m_close_connection(void * sessionH,
                            void * userData)
{
    client_data_t * app_data;
#ifdef WITH_TINYDTLS
    dtls_connection_t * targetP;
#else
    connection_t * targetP;
#endif

    app_data = (client_data_t *)userData;
#ifdef WITH_TINYDTLS
    targetP = (dtls_connection_t *)sessionH;
#else
    targetP = (connection_t *)sessionH;
#endif

    if (targetP == app_data->connList)
    {
        app_data->connList = targetP->next;
        lwm2m_free(targetP);
    }
    else
    {
#ifdef WITH_TINYDTLS
        dtls_connection_t * parentP;
#else
        connection_t * parentP;
#endif

        parentP = app_data->connList;
        while (parentP != NULL && parentP->next != targetP)
        {
            parentP = parentP->next;
        }
        if (parentP != NULL)
        {
            parentP->next = targetP->next;
            lwm2m_free(targetP);
        }
    }
}

#ifdef LWM2M_BOOTSTRAP

static void prv_backup_objects(lwm2m_context_t * context)
{
    uint16_t i;

    for (i = 0; i < BACKUP_OBJECT_COUNT; i++) {
        if (NULL != backupObjectArray[i]) {
            switch (backupObjectArray[i]->objID)
            {
            case LWM2M_SECURITY_OBJECT_ID:
                clean_security_object(backupObjectArray[i]);
                lwm2m_free(backupObjectArray[i]);
                break;
            case LWM2M_SERVER_OBJECT_ID:
                clean_server_object(backupObjectArray[i]);
                lwm2m_free(backupObjectArray[i]);
                break;
            default:
                break;
            }
        }
        backupObjectArray[i] = (lwm2m_object_t *)lwm2m_malloc(sizeof(lwm2m_object_t));
        memset(backupObjectArray[i], 0, sizeof(lwm2m_object_t));
    }

    /*
     * Backup content of objects 0 (security) and 1 (server)
     */
    copy_security_object(backupObjectArray[0], (lwm2m_object_t *)LWM2M_LIST_FIND(context->objectList, LWM2M_SECURITY_OBJECT_ID));
    copy_server_object(backupObjectArray[1], (lwm2m_object_t *)LWM2M_LIST_FIND(context->objectList, LWM2M_SERVER_OBJECT_ID));
}

static void prv_restore_objects(lwm2m_context_t * context)
{
    lwm2m_object_t * targetP;

    /*
     * Restore content  of objects 0 (security) and 1 (server)
     */
    targetP = (lwm2m_object_t *)LWM2M_LIST_FIND(context->objectList, LWM2M_SECURITY_OBJECT_ID);
    // first delete internal content
    clean_security_object(targetP);
    // then restore previous object
    copy_security_object(targetP, backupObjectArray[0]);

    targetP = (lwm2m_object_t *)LWM2M_LIST_FIND(context->objectList, LWM2M_SERVER_OBJECT_ID);
    // first delete internal content
    clean_server_object(targetP);
    // then restore previous object
    copy_server_object(targetP, backupObjectArray[1]);

    // restart the old servers
    LOGD("[prv_restore_objects] ObjectList restored");
}

static void update_bootstrap_info(lwm2m_client_state_t * previousBootstrapState,
        lwm2m_context_t * context)
{
    if (*previousBootstrapState != context->state)
    {
        *previousBootstrapState = context->state;
        switch(context->state)
        {
            case STATE_BOOTSTRAPPING:
#ifdef LWM2M_WITH_LOGS
                LOGD("[update_bootstrap_info] backup security and server objects");
#endif
                prv_backup_objects(context);
                break;
            default:
                break;
        }
    }
}

static void close_backup_object(void) {
    int i;
    for (i = 0; i < BACKUP_OBJECT_COUNT; i++) {
        if (NULL != backupObjectArray[i]) {
            switch (backupObjectArray[i]->objID)
            {
            case LWM2M_SECURITY_OBJECT_ID:
                clean_security_object(backupObjectArray[i]);
                lwm2m_free(backupObjectArray[i]);
                break;
            case LWM2M_SERVER_OBJECT_ID:
                clean_server_object(backupObjectArray[i]);
                lwm2m_free(backupObjectArray[i]);
                break;
            default:
                break;
            }
        }
    }
}
#endif

int lwm2m_create_client(lwm2m_ipa_client_t* const me, char* address, int port, bool dtls, bool is_bootstrap_server, bool ipv4, char* client_name, int life_time, lwm2m_client_connected_t connected_function,
                        lwm2m_client_connection_lost_notification_callback_t connection_lost_function, esim_iot_state_read_callback_t read_state_function, esim_iot_eid_read_callback_t read_eid_function, esim_iot_eim_message_write_callback_t write_eim_message, 
                        esim_iot_ipa_message_read_callback_t read_ipa_message, esim_iot_clear_ipa_message_execute_callback_t execute_clear_ipa_message, void* callbacks_context) 
{
    char server_uri[256];
    int err;
    int server_id = 123; // To global const
    char * pskId = NULL;        /** TODO: DTLS*/
    uint16_t pskLen = -1;       /** TODO: DTLS*/
    char * pskBuffer = NULL;    /** TODO: DTLS*/

    if (dtls) {
        LOGE("[lwm2m_create_client] CoAP DTLS connections is not supported");
        return -eNotSupported;
    }

    client_data_t* client_data = M_malloc(sizeof(client_data_t));
    if (!client_data) {
        LOGE("[lwm2m_create_client] Error allocationg data to the client_data");
        return -eNoMem;
    }

    client_data->addressFamily = ipv4 ? AF_INET : AF_INET6;
    client_data->connList = NULL;
#ifdef LWM2M_BOOTSTRAP
    client_data->previousState = STATE_INITIAL;
    me->bootstrap_server = is_bootstrap_server;
#else
    me->bootstrap_server = false;
#endif

    /* Set Security object */
    if ((err = snprintf(server_uri, sizeof(server_uri), COAP_URI_TEMPLATE, address, port)) < 0) { /** TODO: Support DTLS */
        LOGE("[lwm2m_create_client] Error on write the CoAP URI, err %d", err);
        return err;
    }
    lwm2m_client_objects[0] = get_security_object(server_id, server_uri, pskId, pskBuffer, pskLen, me->bootstrap_server);
    if (NULL == lwm2m_client_objects[0]) {
        LOGE("[lwm2m_create_client] Failed to create security object");
        M_free(client_data);
        return -eFatal;
    }
    client_data->securityObjP = lwm2m_client_objects[0];

    /* Set Server object */
    lwm2m_client_objects[1] = get_server_object(server_id, "U", life_time, false);
    if (NULL == lwm2m_client_objects[1])
    {
        LOGE("[lwm2m_create_client] Failed to create server object");
        M_free(client_data);
        clean_security_object(lwm2m_client_objects[0]);
        lwm2m_free(lwm2m_client_objects[0]);
        return -eFatal;
    }

    /* Set Device object */
    lwm2m_client_objects[2] = get_object_device();
    if (NULL == lwm2m_client_objects[2])
    {
        LOGE("[lwm2m_create_client] Failed to create Device object");
        M_free(client_data);
        clean_security_object(lwm2m_client_objects[0]);
        lwm2m_free(lwm2m_client_objects[0]);
        clean_server_object(lwm2m_client_objects[1]);
        lwm2m_free(lwm2m_client_objects[1]);
        return -eFatal;
    }

    /* Set connected callback function */
    me->connected_callback = connected_function;
    me->connection_lost_callback = connection_lost_function;
    /* Set eSIM IoT object */
    me->esim_iot_callbacks.read_state = read_state_function;
    me->esim_iot_callbacks.read_eid = read_eid_function;
    me->esim_iot_callbacks.esipa_message_from_eim_to_ipa = write_eim_message;
    me->esim_iot_callbacks.esipa_message_from_ipa_to_eim = read_ipa_message;
    me->esim_iot_callbacks.clear_ipa_message = execute_clear_ipa_message;
    /* Set the callbacks context */
    me->context = callbacks_context;
    lwm2m_client_objects[3] = get_esim_iot_object(&me->esim_iot_callbacks, me->context);
    if (NULL == lwm2m_client_objects[3])
    {
        LOGE("[lwm2m_create_client] Failed to create eSIM IoT object");
        M_free(client_data);
        clean_security_object(lwm2m_client_objects[0]);
        lwm2m_free(lwm2m_client_objects[0]);
        clean_server_object(lwm2m_client_objects[1]);
        lwm2m_free(lwm2m_client_objects[1]);
        free_object_device(lwm2m_client_objects[2]);
        return -eFatal;
    }

    LOGI("[LwM2M]\tTrying to bind LWM2M Client to port %s", LOCAL_CLIENT_PORT);
    client_data->sock = create_socket(LOCAL_CLIENT_PORT, client_data->addressFamily);
    if (client_data->sock < 0)
    {
        LOGE("[lwm2m_create_client] Failed to open socket: %d", client_data->sock);
        M_free(client_data);
        clean_security_object(lwm2m_client_objects[0]);
        lwm2m_free(lwm2m_client_objects[0]);
        clean_server_object(lwm2m_client_objects[1]);
        lwm2m_free(lwm2m_client_objects[1]);
        free_object_device(lwm2m_client_objects[2]);
        free_esim_iot_object(lwm2m_client_objects[3]);
        return -eFatal;
    }

    me->lwm2m_client_handler = client_data;
    me->server_hostname = address;
    me->server_port = port;
    me->client_name = client_name;
    me->life_time = life_time;

    return 0;
}

int lwm2m_initialize(lwm2m_ipa_client_t* const me) {
    int result = 0;
    client_data_t* client_data = me->lwm2m_client_handler;

    /*
     * The liblwm2m library is now initialized with the functions that will be in
     * charge of communication
     */
    client_data->lwm2mH = lwm2m_init((void*) client_data);
    if (NULL == client_data->lwm2mH)
    {
        LOGE("[lwm2m_initialize] lwm2m_init() failed");
        return -eFatal;
    }

    /*
     * We configure the liblwm2m library with the name of the client - which shall be unique for each client -
     * the number of objects we will be passing through and the objects array
     */
    result = lwm2m_configure(client_data->lwm2mH, me->client_name, NULL, NULL, OBJ_COUNT, lwm2m_client_objects);
    if (result != 0)
    {
        LOGE("[lwm2m_initialize] lwm2m_configure() failed: 0x%X", result);
        return -eFatal;
    }

    LOGI("[LWM2M]\tLWM2M Client \"%s\" started on port %s", me->client_name, LOCAL_CLIENT_PORT);

    return 0;
}

bool lwm2m_connect(lwm2m_ipa_client_t* const me) {
    int result = 0;
    client_data_t* const client_data = me->lwm2m_client_handler;
    struct timeval tv;
    fd_set readfds;

    tv.tv_sec = 60;
    tv.tv_usec = 0;
    FD_ZERO(&readfds);
    FD_SET(client_data->sock, &readfds);

    /*
        * This function does two things:
        *  - first it does the work needed by liblwm2m (eg. (re)sending some packets).
        *  - Secondly it adjusts the timeout value (default 60s) depending on the state of the transaction
        *    (eg. retransmission) and the time between the next operation
        */
    result = lwm2m_step(client_data->lwm2mH, &(tv.tv_sec));
    switch (client_data->lwm2mH->state)
    {
    case STATE_INITIAL:
        LOGD("[lwm2m_connect] -> State: STATE_INITIAL");
        break;
    case STATE_BOOTSTRAP_REQUIRED:
        LOGD("[lwm2m_connect] -> State: STATE_BOOTSTRAP_REQUIRED");
        break;
    case STATE_BOOTSTRAPPING:
        LOGD("[lwm2m_connect] -> State: STATE_BOOTSTRAPPING");
        break;
    case STATE_REGISTER_REQUIRED:
        LOGD("[lwm2m_connect] -> State: STATE_REGISTER_REQUIRED");
        break;
    case STATE_REGISTERING:
        LOGD("[lwm2m_connect] -> State: STATE_REGISTERING");
        if(client_data->previousState == STATE_READY)
        {
            LOGD("[lwm2m_connect] previous state: %d. Executing the disconnected callback function.");
            me->connection_lost_callback(me->context);
        }
        break;
    case STATE_READY:
        LOGD("[lwm2m_connect] -> State: STATE_READY");
        if(client_data->previousState != STATE_READY)
        {
            LOGD("[lwm2m_connect] previous state: %d. Executing the connected callback function.");
            me->connected_callback(me->context);
        }
        break;
    default:
        LOGD("[lwm2m_connect] -> State: Unknown...");
        break;
    }
    if (result != 0)
    {
        LOGE("[lwm2m_connect] lwm2m_step() failed: 0x%X", result);
#ifdef LWM2M_BOOTSTRAP
        if(client_data->previousState == STATE_BOOTSTRAPPING)
        {
            LOGD("[lwm2m_connect] restore security and server objects");
            prv_restore_objects(client_data->lwm2mH);
            client_data->lwm2mH->state = STATE_INITIAL;
        } else
#endif
            return false;
    }

#ifdef LWM2M_BOOTSTRAP
    update_bootstrap_info(&client_data->previousState, client_data->lwm2mH);
#endif
    /*
        * This part will set up an interruption until an event happen on SDTIN or the socket until "tv" timed out (set
        * with the precedent function)
        */
    result = select(FD_SETSIZE, &readfds, NULL, NULL, &tv);

    if (result < 0)
    {
        if (errno != EINTR)
        {
            LOGE("[lwm2m_connect] Error in select(): %d %s", errno, strerror(errno));
        }
    }
    else if (result > 0)
    {
        uint8_t buffer[MAX_PACKET_SIZE];
        ssize_t numBytes;

        /*
         * If an event happens on the socket
         */
        if (FD_ISSET(client_data->sock, &readfds))
        {
            struct sockaddr_storage addr;
            socklen_t addrLen;

            addrLen = sizeof(addr);

            /*
                * We retrieve the data received
                */
            numBytes = recvfrom(client_data->sock, buffer, MAX_PACKET_SIZE, 0, (struct sockaddr *)&addr, &addrLen);

            if (0 > numBytes)
            {
                LOGE("[lwm2m_connect] Error in recvfrom(): %d %s", errno, strerror(errno));
            }
            else if (numBytes >= MAX_PACKET_SIZE) 
            {
                LOGE("[lwm2m_connect] Received packet >= MAX_PACKET_SIZE");
            } 
            else if (0 < numBytes)
            {
                char s[INET6_ADDRSTRLEN];
                in_port_t port = 0;

#ifdef WITH_TINYDTLS
                dtls_connection_t * connP;
#else
                connection_t * connP;
#endif
                if (AF_INET == addr.ss_family)
                {
                    struct sockaddr_in *saddr = (struct sockaddr_in *)&addr;
                    inet_ntop(saddr->sin_family, &saddr->sin_addr, s, INET6_ADDRSTRLEN);
                    port = saddr->sin_port;
                }
                else if (AF_INET6 == addr.ss_family)
                {
                    struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)&addr;
                    inet_ntop(saddr->sin6_family, &saddr->sin6_addr, s, INET6_ADDRSTRLEN);
                    port = saddr->sin6_port;
                }
                LOGT("[lwm2m_connect] %zd bytes received from [%s]:%hu", numBytes, s, ntohs(port));

                /*
                    * Display it in the STDERR
                    */
                LOG_DATA(eLogTrace, "[lwm2m_connect] bytes received", buffer, (size_t)numBytes);

                connP = connection_find(client_data->connList, &addr, addrLen);
                if (connP != NULL)
                {
                    /*
                        * Let liblwm2m respond to the query depending on the context
                        */
#ifdef WITH_TINYDTLS
                    result = connection_handle_packet(connP, buffer, numBytes);
                    if (0 != result)
                    {
                            LOGE("[lwm2m_connect] error handling message %d",result);
                    }
#else
                    lwm2m_handle_packet(client_data->lwm2mH, buffer, (size_t)numBytes, connP);
#endif
                    //conn_s_updateRxStatistic(lwm2m_client_objects[7], numBytes, false);
                }
                else
                {
                    LOGE("[lwm2m_connect] received bytes ignored!");
                }
            }
        }
    }

    return true;
}

int lwm2m_send_operation(lwm2m_ipa_client_t* const me, const uint16_t object_id, const uint16_t object_instance_id, const uint16_t resource_id, const int16_t resource_instance_id) {
    int rc;
    lwm2m_uri_t lwm2m_uri = {
        .objectId = object_id,
        .instanceId = object_instance_id,
        .resourceId = resource_id,
        .resourceInstanceId = resource_instance_id
    };
    
    if ((rc = lwm2m_send(((client_data_t*)me->lwm2m_client_handler)->lwm2mH, 0, &lwm2m_uri, 1, NULL, NULL)) != 0) {
        LOGE("[lwm2m_send_operation] lwm2m_send failure, rc %d", rc);
        return -eFatal;
    }

    return 0;
}

int lwm2m_disconnect(lwm2m_ipa_client_t* const me) {
    #ifdef WITH_TINYDTLS
        free(pskBuffer); /** TODO: */
    #endif

    #ifdef LWM2M_BOOTSTRAP
        close_backup_object();
    #endif
    lwm2m_close(((client_data_t*)me->lwm2m_client_handler)->lwm2mH);

    return 0;
}

void lwm2m_destroy(lwm2m_ipa_client_t* const me) {
    close(((client_data_t*)me->lwm2m_client_handler)->sock);
    connection_free(((client_data_t*)me->lwm2m_client_handler)->connList);
    M_free(me->lwm2m_client_handler);

    clean_security_object(lwm2m_client_objects[0]);
    lwm2m_free(lwm2m_client_objects[0]);
    clean_server_object(lwm2m_client_objects[1]);
    lwm2m_free(lwm2m_client_objects[1]);
    free_object_device(lwm2m_client_objects[2]);
    free_esim_iot_object(lwm2m_client_objects[3]);
}
#endif
