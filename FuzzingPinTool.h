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

#define DEREFERENCED(x) *(reinterpret_cast<ADDRINT*>(x))

VOID Fuzzer_Image(IMG img, void*);
VOID Fuzzer_Instrunction(INS ins, void*);
VOID Fuzzer_Trace(TRACE trc, void*);

VOID Outline_Image(IMG img, void*);
VOID Outline_Fini(INT32 exitCode, void*);

VOID Test_Routine(RTN rtn, void*);
VOID Test_Instruction(INS ins, void*);
BOOL Test_LoadList(string path);

BOOL Tracker_LoadList(string path);
VOID Tracker_Instruction(INS ins, void*);
VOID Tracker_Fini(INT32 exitCode, void*);

// Common

VOID OutputContext(ofstream *fout, CONTEXT *ctxt);