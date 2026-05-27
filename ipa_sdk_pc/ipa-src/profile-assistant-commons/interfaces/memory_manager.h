/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 * 
 *  @file memory_manager.h
 *  @brief memory manager interface, allocations and deallocations only allowed in this file
 *  
 *  The functions described in this interface needs to be implemented in for each hardware specific
 * 
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
*/
#pragma once
#include "typedefs.h"

/**
 * Allocates the requested memory and returns a pointer to it.
 * @param size is the size of the memory block, in bytes.
 * @return a pointer to the allocated memory, or NULL if the request fails.
*/
void *M_malloc(size_t size);

/**
 * Allocates the requested memory and returns a pointer to it. The difference in M_malloc and M_calloc is that M_malloc does not 
 * set the memory to zero where as M_calloc sets allocated memory to zero.
 * @param nitems the number of elements to be allocated.
 * @param size the size of the element.
 * @return a pointer to the allocated memory, or NULL if the request fails.
*/
void *M_calloc(size_t nitems, size_t size);

/**
 * Attempts to resize the memory block pointed to by ptr that was previously allocated with a call to M_malloc or M_calloc.
 * @param ptr the pointer to a memory block previously allocated with M_malloc, M_calloc or M_realloc to be reallocated. 
 * If this is NULL, a new block is allocated and a pointer to it is returned by the function.
 * @param size the new size for the memory block, in bytes. If it is 0 and ptr points to an existing block of memory, the memory 
 * block pointed by ptr is deallocated and a NULL pointer is returned.
 * @return a pointer to the newly allocated memory, or NULL if the request fails.
*/
void *M_realloc(void *ptr, size_t size);

/**
 * Deallocates the memory previously allocated by a call to M_calloc, M_malloc, or M_realloc
 * @param ptr is the pointer to a memory block previously allocated with M_malloc, M_calloc or M_realloc to be deallocated. 
 * If a null pointer is passed as argument, no action occurs.
 * @return This function does not return any value.
*/
void M_free(void *ptr);