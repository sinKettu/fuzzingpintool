#pragma once

#include <stdio.h>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <time.h>
#include <iostream>

#include "pin.H"
#include "asm/unistd.h"

VOID Tracer_Trace(TRACE trace, void*);
VOID Tracer_Fini(int exitCode, void*);

VOID Fuzzer_Image(IMG img, void*);
VOID Fuzzer_Instrunction(INS ins, void*);
VOID Fuzzer_Trace(TRACE trc, void*);

VOID Fuzzer_Outline(IMG img, void*);
VOID Fuzzer_OutlineOutput(INT32 exitCode, void*);

VOID Fuzzer_Test(RTN rtn, void*);
BOOL Fuzzer_LoadList(string path);