/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 * 
 *  @file serial.h
 *  @brief serial interface, open/close and read/write serial ports is only allowed in this file
 *  
 *  The functions described in this interface needs to be implemented in for each hardware specific
 * 
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
*/
#pragma once
#include "typedefs.h"

/**
 * Open a serial port.
 * 
 * @param serial_port The OS-specific name of a serial port. Must not be NULL.
 * @param serial_port_size The MAX size of serial_port char array.
 * @param baud_rate Baud rate in bits per second for the specified serial port.
 * 
 * @return Pointer to a port structure if the port is open on success, or NULL on failure.
*/
void* open_serial_port(char* serial_port, const size_t serial_port_size, const unsigned int baud_rate);

/**
 * Close a serial port opened with open_serial_port.
 * 
 * @param port Pointer to a port structure. Must not be NULL.
 * 
 * @return 0 if the port is close on success, or a negative error code.
*/
int close_serial_port(void* port);

/**
 * Read bytes from the specified serial port.
 * 
 * @param port Pointer to a port structure. Must not be NULL.
 * @param buffer Buffer in which to store the bytes read. Must not be NULL.
 * @param size Maximum number of bytes to read. Must not be zero.
 * 
 * @return The number of bytes read on success, or a negative error code.
 */
int read_serial_port(void* port, unsigned char* buffer, size_t size);

/**
 * Write bytes to the specified serial port.
 * 
 * @param port Pointer to a port structure. Must not be NULL.
 * @param buffer Buffer containing the bytes to write. Must not be NULL.
 * @param size Requested number of bytes to write.
 * 
 * @return The number of bytes written on success, or a negative error code.
 */
int write_serial_port(void* port, unsigned char* buffer, size_t size);