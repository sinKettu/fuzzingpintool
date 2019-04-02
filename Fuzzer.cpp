#include <stdio.h>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include "FuzzingPinTool.h"
using namespace std;

#define ROUNDS_COUNT 10

ADDRINT headInsAddr = 0;
CONTEXT backup;
int rouns = ROUNDS_COUNT;

VOID headInsCall(ADDRINT head, CONTEXT *ctxt)
{
	if (headInsAddr != 0)
		return;

	headInsAddr = head;
	PIN_SaveContext(ctxt, &backup);
}

VOID tailInsCall()
{
	
	if (headInsAddr == 0 || rouns == 0)
		return;

	CONTEXT restored;
	PIN_SaveContext(&backup, &restored);
	PIN_SetContextReg(&restored, REG_EIP, headInsAddr);
	rouns--;
	PIN_ExecuteAt(&restored);
}

VOID Fuzzer_Routine(RTN rtn, void*)
{
	if (RTN_Valid(rtn) && RTN_Name(rtn).compare("print_test") == 0)
	{
		RTN_Open(rtn);
		INS headIns = RTN_InsHead(rtn);

		INS_InsertCall(
			headIns,
			IPOINT_BEFORE, (AFUNPTR)headInsCall,
			IARG_ADDRINT, INS_Address(headIns),
			IARG_CONTEXT,
			IARG_END
		);

		INS tailIns = RTN_InsTail(rtn);
		INS_InsertCall(
			tailIns,
			IPOINT_BEFORE, (AFUNPTR)tailInsCall,
			IARG_END
		);
		RTN_Close(rtn);
	}
	
}