/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#ifndef SERIAL_TERMIOS
#include <libserialport.h>
#include "serial.h"
#include "log.h"

#define TIMEOUT 5000 //In ms

void* open_serial_port(char* serial_port, const size_t serial_port_size, const unsigned int baud_rate) {
    struct sp_port* port;
	enum sp_return rc;

    if (!serial_port) {
        LOGE("[open_serial_port] serial_port is null");
        return NULL;
    }

    LOGD("[open_serial_port] port name [%s], baud rate %u", serial_port, baud_rate);

	if ((rc = sp_get_port_by_name(serial_port, &port)) != SP_OK) {
		LOGE("[open_serial_port] sp_getport_by_name [%s] failed, rc %d", serial_port, rc);
		return NULL;
	}

    LOGD("[open_serial_port] Opening serial port");
	if ((rc =  sp_open(port, SP_MODE_READ_WRITE)) != SP_OK) {
		LOGE("[open_serial_port] sp_open failed, rc %d", rc);
        sp_free_port(port);
        return NULL;
	}

	LOGD("[open_serial_port] Setting port to %u 8N1, no flow control.", baud_rate);	
	if ((rc =  sp_set_baudrate(port, baud_rate)) != SP_OK) {
		LOGE("[open_serial_port] sp_set_baudrate failed, rc %d", rc);
        goto close_on_error;
	}

	if ((rc = sp_set_bits(port, 8)) != SP_OK) {
		LOGE("[open_serial_port] sp_set_bits failed, rc %d", rc);
        goto close_on_error;
	}
	if ((rc = sp_set_parity(port, SP_PARITY_NONE)) != SP_OK) {
		LOGE("[open_serial_port] sp_set_parity failed, rc %d", rc);
        goto close_on_error;
	}
	if ((rc = sp_set_stopbits(port, 1)) != SP_OK) {
		LOGE("[open_serial_port] sp_set_stopbits failed, rc %d", rc);
        goto close_on_error;
	}
	if ((rc = sp_set_flowcontrol(port, SP_FLOWCONTROL_NONE)) != SP_OK) {
		LOGE("[open_serial_port] sp_set_flowcontrol failed, rc %d", rc);
        goto close_on_error;
	}

	return (void*) port;

close_on_error:
    LOGD("[open_serial_port] Closing the serial port after error detection");
    if ((rc = sp_close(port)) != SP_OK) {
        LOGE("[open_serial_port] Error on close the serial port, rc %d", rc);
    }
    
    sp_free_port(port);
    return NULL;
}

int close_serial_port(void* port) {
    enum sp_return rc;

    if (!port) {
        LOGE("[close_serial_port] port is null");
        return -1;
    }
    
    LOGD("[close_serial_port] Closing serial port");
    if (SP_OK == (rc = sp_close((struct sp_port*) port))) {
        LOGD("[close_serial_port] Serial port closed");
    } else {
        LOGE("[close_serial_port] Error on close the serial port, rc %d", rc);
        return -1;
    }
    
    sp_free_port((struct sp_port*) port);
    LOGD("[close_serial_port] Serial port resources freed");

    return 0;
}

int read_serial_port(void* port, unsigned char* buffer, size_t size) {
    int bytes_read;

    if (!port) {
        LOGE("[read_serial_port] port is null");
        return -1;
    }
    if (!buffer) {
        LOGE("[read_serial_port] buffer is null");
        return -1;
    }

#ifdef DEBUG_SERIAL_PORT_RW
    LOGT("[read_serial_port] Reading %u bytes on port", size);
#endif
    if ((bytes_read = sp_blocking_read((struct sp_port*) port, buffer, size, TIMEOUT)) < 0) {
        LOGE("[read_serial_port] sp_blocking_read failed, rc %d", bytes_read);
        return -1;
    } else {
#ifdef DEBUG_SERIAL_PORT_RW
        LOGT("[read_serial_port] %u bytes read on port", bytes_read);
#endif
        return bytes_read;
    }
}

int write_serial_port(void* port, unsigned char* buffer, size_t size) {
    int bytes_write;

    if (!port) {
        LOGE("[write_serial_port] port is null");
        return -1;
    }
    if (!buffer) {
        LOGE("[write_serial_port] buffer is null");
        return -1;
    }

#ifdef DEBUG_SERIAL_PORT_RW
    LOGT("[write_serial_port] Writing %u bytes on port", size);
#endif
    if ((bytes_write = sp_blocking_write((struct sp_port*) port, buffer, size, TIMEOUT)) < 0) {
        LOGE("[write_serial_port] sp_blocking_read failed, rc %d", bytes_write);
        return -1;
    } else {
        if (bytes_write == size) {
#ifdef DEBUG_SERIAL_PORT_RW
            LOGT("[write_serial_port] %d bytes wrote on port", bytes_write);
#endif
            return bytes_write;
		} else {
			LOGE("[write_serial_port] Failed to write all bytes to port, %d/%u bytes sent.", bytes_write, size);
			return -1;
		}
    }
}
#endif // SERIAL_TERMIOS
