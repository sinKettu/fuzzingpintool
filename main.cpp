#include "FuzzingPinTool.h"
#include <iostream>
#include <vector>
using namespace std;

KNOB<BOOL> KnobOutline(KNOB_MODE_WRITEONCE, "pintool", "outline", "", "Show images and routines");
KNOB<string> KnobTestList(KNOB_MODE_WRITEONCE, "pintool", "test", "error", "List of routines to test");
KNOB<string> KnobTrackerList(KNOB_MODE_WRITEONCE, "pintool", "track", "error", "List of values to track");

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
		TRACE_AddInstrumentFunction(Outline_Trace, 0);
		PIN_AddFiniFunction(Outline_Fini, 0);
	}
	else if (KnobTestList.Value().compare("error"))
	{
		if (Test_LoadList(KnobTestList.Value()))
		{
			RTN_AddInstrumentFunction(Test_Routine2, 0);
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
	else 
	{
		IMG_AddInstrumentFunction(Fuzzer_Image, 0);
		INS_AddInstrumentFunction(Fuzzer_Instrunction, 0);
		TRACE_AddInstrumentFunction(Fuzzer_Trace, 0);
	}

	PIN_StartProgram();

	return 0;
}