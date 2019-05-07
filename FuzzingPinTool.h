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
//VOID Fuzzer_Instrunction(INS ins, void*);
VOID Fuzzer_Trace(TRACE trc, void*);
BOOL Fuzzer_LoadList(string path);

VOID Outline_Image(IMG img, void*);
VOID Outline_Fini(INT32 exitCode, void*);

VOID Test_Routine(RTN rtn, void*);
VOID Test_Instruction(INS ins, void*);
BOOL Test_LoadList(string path);
VOID Test_Fini(INT32 exitCode, void*);

BOOL Tracker_LoadList(string path);
VOID Tracker_Instruction(INS ins, void*);
VOID Tracker_Fini(INT32 exitCode, void*);

BOOL Tracer_LoadList(string path);
VOID Tracer_Trace(TRACE trc, void*);
VOID Tracer_Fini(INT32 code, void*);

// Common

VOID OutputContext(ofstream *fout, CONTEXT *ctxt);
VOID ParseForRoutine(string str, string &imgName, string &rtnName);
VOID ParseForRange(string str, string &imgName, ADDRINT &s, ADDRINT &e);