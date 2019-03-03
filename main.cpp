#include "pin.H"
#include "asm/unistd.h"
#include "MallocFreeOverlows.h"

#include <string>
#include <vector>

struct Routine
{
	std::string Name;
	UINT32 Address;
	UINT64 Size;
	UINT32 StackBegin;
	UINT32 StackEnd;
};

std::vector<Routine> rtnStack;
Routine *Head = nullptr;

VOID DenoteRoutine(const std::string *rtnName, UINT32 rtnAddress, UINT64 rtnSize)
{
	Routine CurrentRoutine;
			CurrentRoutine.Name			= *rtnName;
			CurrentRoutine.Address		= rtnAddress;
			CurrentRoutine.Size			= rtnSize;
			CurrentRoutine.StackBegin	= UINT32_MAX;
			CurrentRoutine.StackEnd		= UINT32_MAX;

	rtnStack.push_back(CurrentRoutine);
	Head = &rtnStack[rtnStack.size() - 1];
	/*if (rtnName->find("main") != std::string::npos)
		printf("\n\n\n!!!\n\n\n");*/
}

VOID StackOverflows_Routine(RTN rtn, void *)
{
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);

		RTN_InsertCall
		(
			rtn,
			IPOINT_BEFORE, (AFUNPTR)DenoteRoutine,
			IARG_PTR, new std::string(RTN_Name(rtn)),
			IARG_ADDRINT, RTN_Address(rtn),
			IARG_UINT64, (UINT64)RTN_Size(rtn),
			IARG_END
		);

		RTN_Close(rtn);
	}
}

VOID PopRoutine(void)
{
	//printf("ret\n");
	if (Head != nullptr)
	{
		//if (Head->Name.find("main") != std::string::npos)
		if (Head->StackBegin != UINT32_MAX && Head->StackEnd != UINT32_MAX)
		{
			//printf("%s 0x%08x 0x%08x\n", Head->Name.c_str(), Head->StackBegin, Head->StackEnd);
		}
		Head--;
		rtnStack.pop_back();
		if (rtnStack.empty())
			Head = nullptr;
	}
}

VOID MonitorRegs(UINT32 ebp, UINT32 esp)
{
	//printf("mon\n");
	if (Head != nullptr)
	{
		if (Head->StackBegin == UINT32_MAX && Head->StackEnd == UINT32_MAX)
		{
			Head->StackBegin = ebp;
			Head->StackEnd = esp;
		}
		else
		{
			if (ebp == esp && ebp < Head->StackBegin)
				Head->StackBegin = ebp;
			else if (esp < ebp && Head->StackBegin == ebp)
				Head->StackEnd = ebp;
		}
	}
}

VOID MonitorStackStoring(UINT32 addr, UINT32 insAddr)
{
	if (Head != nullptr && Head->StackEnd < Head->StackBegin && (addr >= Head->StackEnd && addr <= Head->StackBegin))
	{
		printf("[STACK] 0x%08x: Storing into \"%s\" stack with address 0x%08x\n", insAddr, Head->Name.c_str(), addr);
	}
}

VOID StackOverflows_Instruction(INS ins, void*)
{
	if (INS_IsRet(ins))
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PopRoutine, IARG_END);
	}
	else if (INS_IsStackWrite(ins))
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)MonitorStackStoring,
			IARG_MEMORYWRITE_EA,
			IARG_ADDRINT, INS_Address(ins),
			IARG_END
		);
	}
	else
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)MonitorRegs,
			IARG_REG_VALUE, REG_EBP,
			IARG_REG_VALUE, REG_ESP,
			IARG_END
		);

	}

	/*if (INS_IsRet(ins))
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PopRoutine, IARG_END);
	}
	else if (INS_IsStackWrite(ins))
	{
		INS_InsertCall
		(
			ins, 
			IPOINT_BEFORE, (AFUNPTR)MonitorStackStoring, 
			IARG_MEMORYWRITE_EA, 
			IARG_ADDRINT, INS_Address(ins),
			IARG_END
		);
	}
	else
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)MonitorRegs,
			IARG_REG_VALUE, REG_EBP,
			IARG_REG_VALUE, REG_ESP,
			IARG_END
		);
	}*/
	
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
 	RTN_AddInstrumentFunction(StackOverflows_Routine, 0);
	INS_AddInstrumentFunction(StackOverflows_Instruction, 0);
	//IMG_AddInstrumentFunction(MallocFreeOverflows_Image, 0);
	// INS_AddInstrumentFunction(StackOverflow_Instruction, 0);

//	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();

	return 0;
}

// INS_IsStackWrite