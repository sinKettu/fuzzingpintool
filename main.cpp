#include "pin.H"
#include "asm/unistd.h"
#include "MallocFreeOverlows.h"

#include <string>
#include <vector>

struct Routine
{
	std::string Name;
	UINT32 StackBegin;
	UINT32 StackEnd;
	BOOL Empty;
};

std::vector<Routine> rtnStack;

VOID RtnBegin(const std::string *ins, const std::string *ins_n)
{
	Routine current;
	current.Empty = true;
	rtnStack.push_back(current);
}

VOID RtnEnd()
{
	if (!rtnStack.empty())
		rtnStack.pop_back();
}

VOID StackWriteHandle(RTN *rtn, UINT32 storeAddr, UINT32 insAddr, UINT32 opSize, UINT32 ebp, UINT32 esp)
{
	if (!rtnStack.empty())
	{
		if (rtnStack.back().Empty && RTN_Valid(*rtn))
		{
			rtnStack.back().Name = RTN_Name(*rtn);
			rtnStack.back().StackBegin = ebp;
			rtnStack.back().StackEnd = esp;
			rtnStack.back().Empty = false;
		}

		if (storeAddr >= rtnStack.back().StackEnd && storeAddr <= rtnStack.back().StackBegin)
		{
			printf("[STACK] 0x%08x: Store in \"%s\" with stack borders 0x%08x:0x%08x %d bytes at 0x%08x\n", insAddr, rtnStack.back().Name.c_str(), rtnStack.back().StackEnd, rtnStack.back().StackBegin, opSize, storeAddr);
		}
	}
}

VOID StackOverflows_Instruction(INS ins, void*)
{
	if (INS_IsCall(ins))
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR) RtnBegin,
			IARG_END
		);
	}
	else if (INS_IsRet(ins))
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)RtnEnd,
			IARG_END
		);
	}
	else if (INS_IsMemoryWrite(ins) && INS_OperandCount(ins) == 2)
	{
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)StackWriteHandle,
			IARG_PTR, new RTN(INS_Rtn(ins)),
			IARG_MEMORYWRITE_EA,
			IARG_ADDRINT, INS_Address(ins),
			IARG_MEMORYWRITE_SIZE,
			IARG_REG_VALUE, REG_EBP,
			IARG_REG_VALUE, REG_ESP,
			IARG_END
		);
	}
	else
	{
		//
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
	//RTN_AddInstrumentFunction(StackOverflows_Routine, 0);
	INS_AddInstrumentFunction(StackOverflows_Instruction, 0);

//	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();

	return 0;
}