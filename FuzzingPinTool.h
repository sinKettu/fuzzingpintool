#pragma once

#include "pin.H"
#include "asm/unistd.h"

VOID Tracer_Trace(TRACE trace, void*);
VOID Tracer_Fini(int exitCode, void*);

VOID Fuzzer_Image(IMG img, void*);
VOID Fuzzer_Instrunction(INS ins, void*);
VOID Fuzzer_Trace(TRACE trc, void*);