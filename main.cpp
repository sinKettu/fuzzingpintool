#include "FuzzingPinTool.h"
#include <iostream>
#include <vector>
using namespace std;

KNOB<BOOL> KnobOutline(KNOB_MODE_WRITEONCE, "pintool", "outline", "", "Show images and routines");
KNOB<string> KnobTestList(KNOB_MODE_WRITEONCE, "pintool", "test", "error", "List of routines to test");
KNOB<string> KnobTrackerList(KNOB_MODE_WRITEONCE, "pintool", "track", "error", "List of values to track");
KNOB<string> KnobTracerList(KNOB_MODE_WRITEONCE, "pintool", "trace", "error", "List of images to get trace");
KNOB<string> KnobFuzzerList(KNOB_MODE_WRITEONCE, "pintool", "fuzz", "error", "List of images to get trace");

int main(int argc, char *argv[])
{
	printf("Hello\n\n");
	
	PIN_InitSymbols();	// Необходима, чтобы была возможность искать функции в образе
	
	if (PIN_Init(argc, argv))
	{
		return -1;
	}

	PIN_SetSyntaxIntel();
	if (KnobOutline.Value())
	{
		IMG_AddInstrumentFunction(Outline_Image, 0);
		PIN_AddFiniFunction(Outline_Fini, 0);
	}
	else if (KnobTestList.Value().compare("error"))
	{
		if (Test_LoadList(KnobTestList.Value()))
		{
			RTN_AddInstrumentFunction(Test_Routine, 0);
			INS_AddInstrumentFunction(Test_Instruction, 0);
			PIN_AddFiniFunction(Test_Fini, 0);
		}
	}
	else if (KnobTrackerList.Value().compare("error"))
	{
		if (Tracker_LoadList(KnobTrackerList.Value()))
		{
			INS_AddInstrumentFunction(Tracker_Instruction, 0);
			PIN_AddFiniFunction(Tracker_Fini, 0);
		}
	}
	else if (KnobTracerList.Value().compare("error"))
	{
		if (Tracer_LoadList(KnobTracerList.Value()))
		{
			TRACE_AddInstrumentFunction(Tracer_Trace, 0);
			PIN_AddFiniFunction(Tracer_Fini, 0);
		}
	}
	else if (KnobFuzzerList.Value().compare("error"))
	{
		if (Fuzzer_LoadList(KnobFuzzerList.Value()))
		{
			IMG_AddInstrumentFunction(Fuzzer_Image, 0);
			//INS_AddInstrumentFunction(Fuzzer_Instrunction, 0);
			TRACE_AddInstrumentFunction(Fuzzer_Trace, 0);
		}
	}

	PIN_StartProgram();

	return 0;
}