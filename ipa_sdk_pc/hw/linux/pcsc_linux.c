/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2024-2024
 */
#ifdef ENABLE_PCSC
#include <winscard.h>
#include <stdio.h> 
#include <pcsclite.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "log.h"
#include "pcsc.h"
#include "memory_manager.h"


struct pcsc_reader_s {
	const char* reader_name; /* The name of the reader that contains the target card. */
	SCARDCONTEXT hContext; /* A handle that identifies the resource manager context. The resource manager context is set by a previous call to SCardEstablishContext. */
	SCARDHANDLE hCard; /* A handle that identifies the connection to the smart card in the designated reader. */
	SCARD_IO_REQUEST pioSendPci; /* A pointer to the protocol header structure for the instruction. This buffer is in the format of an SCARD_IO_REQUEST structure */
};


pcsc_reader_t* pcsc__establish_reader(const char* reader_name) {
	LONG rv;
	pcsc_reader_t* pcsc_reader;

	if (reader_name == NULL) {
		LOGE("[PCSC]\tThe reader_name parameter is null");
		return NULL;
	}

	if (strlen(reader_name) == 0) {
		LOGE("[PCSC]\tThe reader_name parameter is empty");
		return NULL;
	}

	pcsc_reader = (pcsc_reader_t*)M_malloc(sizeof(pcsc_reader_t));
	if (!pcsc_reader) {
		LOGE("[PCSC]\t[make_pcsc_reader] Can't allocate data to pcsc_reader");
		return NULL;
	}

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &(pcsc_reader->hContext));
	if (rv != SCARD_S_SUCCESS) {
		LOGE("[PCSC]\tFailed to establish context, error: %ld",rv);
		M_free(pcsc_reader);
		return NULL;
	}
	pcsc_reader->reader_name = reader_name;
	return pcsc_reader;
}

int pcsc__connect_reader(pcsc_reader_t* pcsc_reader) {
	DWORD dwActiveProtocol;
	LONG rv;

	if (pcsc_reader == NULL) {
		LOGE("[PCSC]\tThe pcsc_reader parameter is null");
		return -EINVAL;
	}

	rv = SCardConnect(pcsc_reader->hContext, pcsc_reader->reader_name, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &(pcsc_reader->hCard), &dwActiveProtocol);
	if (rv != SCARD_S_SUCCESS) {
		LOGE("[PCSC]\tFailed to connect, error: %ld", rv);
		return -eFatal;
	}

	switch (dwActiveProtocol) {
	case SCARD_PROTOCOL_T0:
		pcsc_reader->pioSendPci = *SCARD_PCI_T0;
		break;

	case SCARD_PROTOCOL_T1:
		pcsc_reader->pioSendPci = *SCARD_PCI_T1;
		break;
	default:
		LOGE("[PCSC]\tFailed to connect, there is no active protocol, dwActiveProtocol: %lu", dwActiveProtocol);
		return -eFatal;
	}

	return eOk;
}

int pcsc__transmit_to_reader(pcsc_reader_t* pcsc_reader, uint8_t* send_buffer, const uint32_t send_buffer_size, uint8_t* receive_buffer, unsigned long receive_buffer_size) {
	DWORD received;
	LONG rv;

	if (pcsc_reader == NULL) {
		LOGE("[PCSC]\tThe pcsc_reader parameter is null");
		return -EINVAL;
	}

	if (send_buffer == NULL) {
		LOGE("[PCSC]\tThe send_buffer parameter is null");
		return -EINVAL;
	}

	if (receive_buffer == NULL) {
		LOGE("[PCSC]\tThe receive_buffer parameter is null");
		return -EINVAL;
	}

	if (receive_buffer_size == 0) {
		LOGE("[PCSC]\tThe receive_buffer_size is zero");
		return -EINVAL;
	}

	received = receive_buffer_size;

	rv = SCardTransmit(pcsc_reader->hCard, &(pcsc_reader->pioSendPci), send_buffer, send_buffer_size, NULL, receive_buffer, &received);
	if (rv != SCARD_S_SUCCESS) {
		LOGE("[PCSC]\tFailed to transmit,error: %ld", rv);
		return -eFatal;
	}

	return received;
}

int pcsc__disconnect_reader(pcsc_reader_t* pcsc_reader) {
	LONG rv;

	if (pcsc_reader == NULL) {
		LOGE("[PCSC]\tThe pcsc_reader parameter is null");
		return -EINVAL;
	}

	rv = SCardDisconnect(pcsc_reader->hCard, SCARD_LEAVE_CARD);
	if (rv != SCARD_S_SUCCESS) {
		LOGE("[PCSC]\tFailed to disconnect, error: %ld", rv);
		return -eFatal;
	}
	return eOk;
}

int pcsc__disconnect_reader_reset_uicc(pcsc_reader_t* pcsc_reader) {
	LONG rv;

	if (!pcsc_reader) {
		LOGE("[PCSC] The pcsc_reader parameter is null");
		return -EINVAL;
	}

	rv = SCardDisconnect(pcsc_reader->hCard, SCARD_RESET_CARD);
	if (rv != SCARD_S_SUCCESS) {
		LOGE("[PCSC] Failed to disconnect with reset card, error: %ld", rv);
		return -eFatal;
	}
	return eOk;
}

int pcsc__release_reader(pcsc_reader_t** pcsc_reader) {
	LONG rv;

	if (pcsc_reader == NULL || *pcsc_reader == NULL) {
		LOGE("[PCSC]\tThe pcsc_reader parameter is null");
		return -EINVAL;
	}

	rv = SCardReleaseContext((*pcsc_reader)->hContext);
	if (rv != SCARD_S_SUCCESS) {
		LOGE("[PCSC]\tFailed to release context, error: %ld", rv);
		return -eFatal;
	}

	M_free(*pcsc_reader);
	*pcsc_reader = NULL;
	return eOk;
}

extern void pcsc__list_reader() {
	LONG lReturn;
	LPSTR pmszReaders = NULL;
	DWORD pmszReadersLen = 0;
	DWORD pmszReadersOffset = 0;
	SCARDCONTEXT hContext;

	printf("Retrieving the list of Card Readers...\n");

	lReturn = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	if (lReturn != SCARD_S_SUCCESS) {
		printf("Failed to establish context, error: %ld", lReturn);
		return;
	}
	
	lReturn = SCardListReaders(hContext, NULL, NULL, &pmszReadersLen);
	switch (lReturn)
	{
	case SCARD_E_NO_READERS_AVAILABLE:
		printf("No card reader found\n");
		break;
	case SCARD_S_SUCCESS:
		// Allocate space to hold the Readers list
		pmszReaders = malloc(pmszReadersLen);
		if (!pmszReaders) {
			printf("Error allocating data to print the list\n");
			goto list_readers_release_context;
		}
		// Write the readers list into the buffer
		lReturn = SCardListReaders(hContext, NULL, pmszReaders, &pmszReadersLen);
		if (lReturn != SCARD_S_SUCCESS) {
			printf("Error listing the Card Readers after success, rc %ld\n", lReturn);
			free(pmszReaders);
			goto list_readers_release_context;
		}
		// Print the readers list
		printf("Available readers:\n");
		while (pmszReadersOffset < pmszReadersLen-1) {
			printf(" - \"%s\"\n", pmszReaders + pmszReadersOffset);
			pmszReadersOffset += strlen(pmszReaders + pmszReadersOffset) + 1;
		}
		free(pmszReaders);
		pmszReaders = NULL;
		break;	
	default:
		printf("Error listing the Card Readers, rc %ld\n", lReturn);
		break;
	}

list_readers_release_context:	
	lReturn = SCardReleaseContext(hContext);
	if (lReturn != SCARD_S_SUCCESS) {
		printf("Failed to release context, error: %ld", lReturn);
	}
}
#endif