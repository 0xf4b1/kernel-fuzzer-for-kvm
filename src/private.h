#ifndef PRIVATE_H
#define PRIVATE_H

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>

#include <capstone.h>

#include "signal.h"
#include "vmi.h"
#include "afl.h"
#include "tracer.h"

char *domain;
char *json;
FILE *input_file;
char *input_path;
size_t input_size;
size_t input_limit;
unsigned char *input;
bool afl;
bool crash;
bool debug;
bool loopmode;
addr_t address;
addr_t start;
addr_t target;
addr_t module_start;
unsigned long limit;

vmi_instance_t vmi;
os_t os;
page_mode_t pm;
int interrupted;

uint8_t start_byte;
uint8_t target_byte;

csh cs_handle;

enum coverage { DYNAMIC, FULL, BLOCK, EDGE };
enum coverage mode;
char *bp_file;
bool coverage_enabled;

#endif
