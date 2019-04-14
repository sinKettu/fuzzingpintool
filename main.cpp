#include "FuzzingPinTool.h"
#include <iostream>
#include <vector>
using namespace std;

KNOB<BOOL> KnobOutline(KNOB_MODE_WRITEONCE, "pintool", "outline", "", "Show images and routines");
KNOB<string> KnobTestList(KNOB_MODE_WRITEONCE, "pintool", "test", "error", "List of routines to test");

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
		IMG_AddInstrumentFunction(Fuzzer_Outline, 0);
		PIN_AddFiniFunction(Fuzzer_OutlineOutput, 0);
	}
	else if (KnobTestList.Value().compare("error"))
	{
		if (Fuzzer_LoadList(KnobTestList.Value()))
		{
			RTN_AddInstrumentFunction(Fuzzer_RtnTest, 0);
			INS_AddInstrumentFunction(Fuzzer_InsTest, 0);
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