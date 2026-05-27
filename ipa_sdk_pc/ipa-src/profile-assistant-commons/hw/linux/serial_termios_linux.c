/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#ifdef SERIAL_TERMIOS
#include <errno.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "memory_manager.h"
#include "serial.h"
#include "log.h"

void* open_serial_port(char* serial_port, const size_t serial_port_size, const unsigned int baud_rate) {
	int rc, fd;
	int *fd_ret;
	struct termios attrs;

    if (!serial_port) {
        LOGE("[open_serialport] serial_port is null");
        return NULL;
    }

    LOGD("[open_serialport] port name [%s], baud rate %u", serial_port, baud_rate);

    LOGD("[open_serialport] Opening serial port");
	if ((fd = open(serial_port, O_RDWR | O_NOCTTY)) == -1) {
		LOGE("[open_serialport] open [%s] failed, errno %d", serial_port, errno);
		return NULL;
	}

	if ((fd_ret = (int *) M_malloc(sizeof(int))) == NULL) {
		LOGE("[open_serialport] M_malloc failed");
		close(fd);
		return NULL;
	}

	*fd_ret = fd;

	if ((rc = tcgetattr(fd, &attrs)) == -1) {
		LOGE("[open_serialport] tcgetattr [%s] failed, errno %d", serial_port, errno);
		M_free(fd_ret);
		close(fd);
		return NULL;
	}

	LOGD("[open_serialport] Setting port to %u 8N1, no flow control.", baud_rate);	
	// Setting the Baud rate
	cfsetispeed(&attrs, B9600); /* Set Read  Speed as 9600                       */
	cfsetospeed(&attrs, B9600); /* Set Write Speed as 9600                       */
	
	// 8N1 Mode
	attrs.c_cflag &= ~PARENB;   /* Disables the Parity Enable bit(PARENB),So No Parity   */
	attrs.c_cflag &= ~CSTOPB;   /* CSTOPB = 2 Stop bits,here it is cleared so 1 Stop bit */
	attrs.c_cflag &= ~CSIZE;    /* Clears the mask for setting the data size             */
	attrs.c_cflag |= CS8;      /* Set the data bits = 8                                 */
	
	attrs.c_cflag &= ~CRTSCTS;       /* No Hardware flow Control                         */
	attrs.c_cflag |= (CREAD | CLOCAL | HUPCL); /* Enable receiver,Ignore Modem Control lines       */

	// Disable canonical mode, use raw
	attrs.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IMAXBEL | IXON);
	attrs.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	attrs.c_oflag &= ~OPOST;

	attrs.c_cc[VMIN] = 0;
	attrs.c_cc[VTIME] = 0;
	if (tcsetattr(fd, TCSANOW, &attrs) != 0) {
		LOGE("[open_serialport] tcsetattr [%s] failed, errno %d", serial_port, errno);
		M_free(fd_ret);
		close(fd);
		return NULL;
	}
	LOGD("[open_serialport] Port attributes set succesfully");

	return (void*) (fd_ret);
}

int close_serial_port(void* port) {
    if (!port) {
        LOGE("[close_serial_port] port is null");
        return -1;
    }

    LOGD("[close_serial_port] Closing serial port");
    close (* (int *)port);
    M_free(port);

    return 0;
}

int read_serial_port(void* port, unsigned char* buffer, size_t size) {
    int bytes_read, fd, ret, i;

    if (!port) {
        LOGE("[read_serial_port] port is null");
        return -1;
    }
    if (!buffer) {
        LOGE("[read_serial_port] buffer is null");
        return -1;
    }
    if (size == 0) {
        LOGI("[read_serial_port size is 0");
        return 0;
    }
    fd = * (int *) port;

#ifdef DEBUG_SERIAL_PORT_RW
    LOGT("[read_serial_port] Reading %u bytes on port", size);
#endif
    bytes_read = 0;
    for (i=0; i<10; i++) {
        if ((ret = read(fd, buffer, (size - bytes_read))) < 0) {
            LOGE("[read_serial_port] read failed, errno %d", errno);
            return -1;
        }
        bytes_read += ret;
        buffer += ret;
        if (bytes_read >= size)
            break;
        usleep(10000);
    }
#ifdef DEBUG_SERIAL_PORT_RW
    LOGT("[read_serial_port] %u bytes read on port", bytes_read);
#endif
    return bytes_read;
}

int write_serial_port(void* port, unsigned char* buffer, size_t size) {
    int bytes_write, fd;

    if (!port) {
        LOGE("[write_serial_port] port is null");
        return -1;
    }
    if (!buffer) {
        LOGE("[write_serial_port] buffer is null");
        return -1;
    }
    if (size == 0) {
        LOGI("[write_serial_port] size = 0");
        return 0;
    }
    fd = * (int *)port;

#ifdef DEBUG_SERIAL_PORT_RW
    LOGT("[write_serial_port] Writing %u bytes on port", size);
#endif
    if ((bytes_write = write(fd, buffer, size)) < 0) {
        LOGE("[write_serial_port] write failed, errno %d, ", errno);
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
