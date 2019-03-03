#include "pin.H"
#include "asm/unistd.h"
#include "MallocFreeOverlows.h"

#include <string>
#include <vector>

struct Routine
{
	std::string Name;
	UINT32 Head;
	UINT32 StackBegin;
	UINT32 StackEnd;
};

//std::vector<Routine> rtnStack;
//Routine *Head = nullptr;
Routine CurrentRoutine;

VOID DenoteRoutine(const std::string *rtnName, UINT32 headAddr)
{
	
	printf("%s\n", *rtnName->c_str());
	CurrentRoutine.Name = *rtnName;
	CurrentRoutine.Head = headAddr;
	CurrentRoutine.StackBegin = UINT32_MAX;
	CurrentRoutine.StackEnd = UINT32_MAX;
}

VOID StackOverflows_Routine(RTN rtn, void *)
{
	printf("*\n");
	if (RTN_Valid(rtn))
	{
		printf("!\n");
		RTN_Open(rtn);
		RTN_InsertCall(
			rtn, 
			IPOINT_BEFORE, (AFUNPTR)DenoteRoutine, 
			IARG_PTR, new std::string(RTN_Name(rtn)), 
			IARG_ADDRINT, INS_Address((RTN_InsHead(rtn))),
			IARG_END
		);
		RTN_Close(rtn);
	}
}

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
	RTN_AddInstrumentFunction(StackOverflows_Routine, 0);

//	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();

	return 0;
}