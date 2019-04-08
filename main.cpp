#include "FuzzingPinTool.h"
#include <iostream>
#include <vector>
using namespace std;

int main(int argc, char *argv[])
{
	printf("Hello\n\n");

	PIN_InitSymbols();                            // Необходима, чтобы была возможность искать функции в образе
	if (PIN_Init(argc, argv))
	{
		return -1;
	}

	PIN_SetSyntaxIntel();
	
	IMG_AddInstrumentFunction(Fuzzer_Image, 0);
	INS_AddInstrumentFunction(Fuzzer_Instrunction, 0);
	TRACE_AddInstrumentFunction(Fuzzer_Trace, 0);

	PIN_StartProgram();

	return 0;
}