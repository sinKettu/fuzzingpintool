#include <stdio.h>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include "FuzzingPinTool.h"

VOID RtnCallBefore(UINT32 headAddr, const CONTEXT *ctxt, UINT32 a, UINT32* b)
{
	printf("0x%08x\n", headAddr);
	printf("EAX: 0x%08x\n", PIN_GetContextReg(ctxt, REG_EAX));
	UINT32 *c = b;
	//B*(c-1) = 7;
	printf("0x%08x 0x%08x 0x%08x 0x%08x\n", PIN_GetContextReg(ctxt, REG_ESP), a, b+1, *(c+1));
}

VOID Fuzzer_Routine(RTN rtn, void*)
{
	if (RTN_Valid(rtn) && RTN_Name(rtn).compare("print_test") == 0)
	{
		RTN_Open(rtn);
		INS headIns = RTN_InsHead(rtn);
		INS_InsertCall(
			headIns,
			IPOINT_BEFORE, (AFUNPTR)RtnCallBefore,
			IARG_ADDRINT, INS_Address(headIns),
			IARG_CONST_CONTEXT,
			IARG_REG_VALUE, REG_ESP,
			IARG_REG_REFERENCE, REG_ESP,
			IARG_END
		);
		RTN_Close(rtn);
	}
	
}