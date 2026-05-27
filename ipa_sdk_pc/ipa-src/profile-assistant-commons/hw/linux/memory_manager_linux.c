/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 * 
 *  @file memory_manager_linux.c
 *  @brief Implementation for Linux devices of the functions described in the file memory_manager.h
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
*/
#include <stdlib.h>
#include "memory_manager.h"
#ifdef DEBUG_ALLOCATIONS
#include "log.h"

static unsigned long long g_allocations = 0;
static unsigned long long g_deallocations = 0;
#endif

void *M_malloc(size_t size) {
#ifndef STACK_BASED_HEAP
	void *ptr = malloc(size);
#else
	// TODO: Implement STACK BASED HEAP allocator for debugging or embedded devices when necesary. MBEDTLS has a sample implementation about this.
	void *ptr = malloc(size);
#endif
#ifdef DEBUG_ALLOCATIONS
	LOGT("** malloc (%zu) -> %p, current allocations %llu", size, ptr, ++g_allocations);
#endif
	return ptr;
}

void *M_calloc(size_t nitems, size_t size) {
#ifndef STACK_BASED_HEAP
	void *ptr = calloc(nitems, size);
#else
	// TODO: Implement STACK BASED HEAP allocator for debugging or embedded devices when necesary. MBEDTLS has a sample implementation about this.
	void *ptr = calloc(nitems, size);
#endif
#ifdef DEBUG_ALLOCATIONS
	LOGT("** calloc (%zu, %zu) -> %p, current allocations %llu", nitems, size, ptr, ++g_allocations);
#endif
	return ptr;
}

void *M_realloc(void *ptr, size_t size) {
#ifdef DEBUG_ALLOCATIONS
	LOGT("** realloc (0x%p)", ptr);
#endif
#ifndef STACK_BASED_HEAP
	void *new_ptr = realloc(ptr, size);
#else
	// TODO: Implement STACK BASED HEAP allocator for debugging or embedded devices when necesary. MBEDTLS has a sample implementation about this.
	void *new_ptr = realloc(ptr, size);
#endif
#ifdef DEBUG_ALLOCATIONS
	if (ptr == NULL && new_ptr != NULL) {
		g_allocations++;
	}
	LOGT("** realloc (%zu) -> %p, current allocations %llu", size, new_ptr, g_allocations);
#endif
	return new_ptr;
}

void M_free(void *ptr) {
#ifdef DEBUG_ALLOCATIONS
	LOGT("**** M_free(%p)", ptr);
#endif
	if (ptr != NULL) {
#ifdef DEBUG_ALLOCATIONS
		LOGT("** free %p, current deallocations %llu", ptr, ++g_deallocations);
#endif
#ifndef STACK_BASED_HEAP
		free(ptr);
#else
		// TODO: Implement STACK BASED HEAP allocator for debugging or embedded devices when necesary. MBEDTLS has a sample implementation about this.
		free(ptr);
#endif
	}
}
