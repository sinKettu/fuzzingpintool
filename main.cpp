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

VOID StackWriteHandle(UINT32 addr, RTN *rtn, UINT32 ebp, UINT32 esp)
{
	if (!rtnStack.empty())
	{
		if (rtnStack.back().Empty && RTN_Valid(*rtn))
		{
			rtnStack.back().Name = RTN_Name(*rtn);
			//rtnStack.back().Head = INS_Address(RTN_InsHead(*rtn));
			rtnStack.back().StackBegin = ebp;
			rtnStack.back().StackEnd = esp;
			rtnStack.back().Empty = false;
		}
		
		printf("[STACK] Store in \"%s\" with stack borders 0x%08x:0x%08x at 0x%08x\n", rtnStack.back().Name.c_str(), rtnStack.back().StackEnd, rtnStack.back().StackBegin, addr);
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
	else if (INS_IsStackWrite(ins) && INS_Opcode(ins) == XED_ICLASS_MOV)
	{
		//RTN cur_rtn = INS_Rtn(ins);
		INS_InsertCall
		(
			ins,
			IPOINT_BEFORE, (AFUNPTR)StackWriteHandle,
			IARG_MEMORYOP_EA, 0,
			IARG_PTR, new RTN(INS_Rtn(ins)),
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