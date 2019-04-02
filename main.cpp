#include "pin.H"
#include "asm/unistd.h"
#include "FuzzingPinTool.h"

int main(int argc, char *argv[])
{
	printf("Hello\n\n");

	PIN_InitSymbols();                            // Необходима, чтобы была возможность искать функции в образе
	if (PIN_Init(argc, argv))
	{
		return -1;
	}

	PIN_SetSyntaxIntel();
	
	//IMG_AddInstrumentFunction(MallocFreeOverflows_Image, 0);
	//INS_AddInstrumentFunction(MallocFreeOverflows_Instruction, 0);

	//IMG_AddInstrumentFunction(StackOverflows_Image, 0);
	//INS_AddInstrumentFunction(StackOverflows_Instruction, 0);
	//RTN_AddInstrumentFunction(StackOverflows_Routine, 0);
	//INS_AddInstrumentFunction(StackOverflows_Instruction, 0);

	//PIN_AddFiniFunction(MallocFreeOverflows_Fini, 0);

	TRACE_AddInstrumentFunction(Tracer_Trace, 0);
	PIN_AddFiniFunction(Tracer_Fini, 0);

	PIN_StartProgram();

	return 0;
}