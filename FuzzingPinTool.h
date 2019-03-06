#pragma once

#include "pin.H"
#include "asm/unistd.h"

VOID MallocFreeOverflows_Image(IMG img, void *);

VOID MallocFreeOverflows_Instruction(INS ins, void*);

VOID StackOverflows_Instruction(INS ins, void*);
