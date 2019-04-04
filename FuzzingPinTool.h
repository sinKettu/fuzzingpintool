#pragma once

#include "pin.H"
#include "asm/unistd.h"

VOID MallocFreeOverflows_Image(IMG img, void *);
VOID MallocFreeOverflows_Instruction(INS ins, void*);
VOID MallocFreeOverflows_Fini(INT32 code, VOID *);

VOID Tracer_Trace(TRACE trace, void*);
VOID Tracer_Fini(int exitCode, void*);

VOID Fuzzer_Image(IMG img, void*);
VOID Fuzzer_Instrunction(INS ins, void*);
VOID Fuzzer_SysCall(THREADID id, CONTEXT *ctxt, SYSCALL_STANDARD std, void*);

VOID StackOverflows_Instruction(INS ins, void*);
