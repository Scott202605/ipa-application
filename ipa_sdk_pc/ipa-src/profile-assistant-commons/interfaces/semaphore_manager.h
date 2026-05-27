/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 * 
 *  @file semaphore_manager.h
 *  @brief semaphore interface. Semaphores are data type used to control access to a common resource
 *  
 *  The functions described in this interface needs to be implemented in for each hardware specific
 * 
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
*/
#pragma once
#include "typedefs.h"

typedef struct semaphore_s semaphore_t; // Hardware specific semaphore handler

/**
 * This function creates a semaphore.
 * See also semaphore_destroy()
 * 
 * @return Pointer to semaphore_t structure if the semaphore is created successfully. Otherwise, an NULL is returned.
*/
semaphore_t *make_semaphore();

/**
 * This function takes the semaphore (to lock an unlocked common resource)
 * 
 * @param semaphore A valid semaphore_t handle from a successful call to make_semaphore().
 * 
 * @return 0 if the semaphore is taken successfully. If the semaphore was already taken before calling this function (the resource was locked), 
 * a negative error code is returned.
 */
int semaphore_take(semaphore_t *semaphore);

/**
 * This function gives the semaphore (to unlock the common resource)
 * 
 * @param semaphore A valid semaphore_t handle from a successful call to make_semaphore().
 * 
 * @return This function does not return any value.
*/
void semaphore_give(semaphore_t *semaphore);

/**
 * This function is used to deallocate possible memory allocations made in make_semaphore().
 * 
 * @param semaphore A valid semaphore_t handle from a successful call to make_semaphore().
 * 
 * @return This function does not return any value.
*/
void semaphore_destroy(semaphore_t *semaphore);