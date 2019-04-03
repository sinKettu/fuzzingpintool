#include <stdio.h>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include "FuzzingPinTool.h"
using namespace std;

#define ROUNDS_COUNT 10
#define FUNCTION_ARGUMENTS vector<pair<ADDRINT, UINT32>>

ADDRINT headInsAddr = 0;
CONTEXT backup;
int rouns = ROUNDS_COUNT;

ofstream fout;
BOOL pushDetected = false;
BOOL callDetected = false;
FUNCTION_ARGUMENTS tmp;

vector<CONTEXT> savedContexts;
vector<ADDRINT> headInstructions;
vector<FUNCTION_ARGUMENTS> funcArgs;
vector<pair<ADDRINT, UINT32>> localVars;
vector<UINT32> lvSeparators;

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

VOID Fuzzer_Image(IMG img, void*)
{
	if (IMG_IsMainExecutable(img))
	{
		fout.open("test.txt", ios::app);
		fout << IMG_Name(img) << "\n";
		fout.close();
	}
}

VOID ShowContext(CONTEXT *ctxt)
{
	printf("EAX: 0x%08x\t", PIN_GetContextReg(ctxt, REG_EAX));
	printf("EBX: 0x%08x\t", PIN_GetContextReg(ctxt, REG_EBX));
	printf("ECX: 0x%08x\t", PIN_GetContextReg(ctxt, REG_ECX));
	printf("EDX: 0x%08x\n", PIN_GetContextReg(ctxt, REG_EDX));
	printf("ESI: 0x%08x\t", PIN_GetContextReg(ctxt, REG_ESI));
	printf("EDI: 0x%08x\t", PIN_GetContextReg(ctxt, REG_EDI));
	printf("ESP: 0x%08x\t", PIN_GetContextReg(ctxt, REG_ESP));
	printf("EBP: 0x%08x\n", PIN_GetContextReg(ctxt, REG_EBP));
}

VOID ShowFunctionArguments(FUNCTION_ARGUMENTS args)
{
	FUNCTION_ARGUMENTS::iterator iter;
	for (iter = args.begin(); iter != args.end(); iter++)
		printf("0x%08x --> 0x%08x\n", iter->first, iter->second);
}

VOID HandlePush(ADDRINT esp)
{
	UINT32 val = *(reinterpret_cast<ADDRINT*>(esp));
	tmp.push_back(make_pair(esp, val));
	pushDetected = true;
}

VOID HandleCall(ADDRINT addr)
{
	headInsAddr = addr;
	callDetected = true;
	pushDetected = false;
	funcArgs.push_back(tmp);
	tmp.clear();
}

VOID HandleRtnHead(ADDRINT addr, CONTEXT *ctxt, const string *name)
{
	CONTEXT tmp;
	PIN_SaveContext(ctxt, &tmp);
	savedContexts.push_back(tmp);
	headInstructions.push_back(addr);
	callDetected = false;
	
	printf("\n%s\n", name->c_str());
	printf("[HEAD] 0x%08x\n", headInstructions.back());
	if (!funcArgs.back().empty())
	{
		printf("[ARGS]\n");
		ShowFunctionArguments(funcArgs.back());
	}
	printf("[CONTEXT]\n");
	ShowContext(&savedContexts.back());
	printf("\n");
}

VOID ResetSavedPushes()
{
	tmp.clear();
	pushDetected = false;
}

VOID Fuzzer_Instrunction(INS ins, void*)
{
	PIN_LockClient();
	IMG img = IMG_FindByAddress(INS_Address(ins));
	PIN_UnlockClient();

	if (!(IMG_Valid(img) && IMG_IsMainExecutable(img)))
		return;

	if (INS_Opcode(ins) == XED_ICLASS_PUSH)
	{
		INS_InsertCall(
			ins,
			IPOINT_AFTER, (AFUNPTR)HandlePush,
			IARG_REG_VALUE, REG_ESP,
			IARG_END
		);
	}
	else if (INS_IsCall(ins))
	{
		INS_InsertCall(
			ins,
			IPOINT_BEFORE, (AFUNPTR)HandleCall,
			IARG_END
		);
	}
	else if (callDetected)
	{
		RTN rtn = RTN_FindByAddress(INS_Address(ins));
		if (RTN_Valid(rtn))
		{
			const string *name = &RTN_Name(rtn);
			INS_InsertCall(
				ins,
				IPOINT_BEFORE, (AFUNPTR)HandleRtnHead,
				IARG_ADDRINT, INS_Address(ins),
				IARG_CONTEXT,
				IARG_PTR, name,
				IARG_END
			);
		}
	}
	else if (pushDetected)
	{
		INS_InsertCall(
			ins,
			IPOINT_BEFORE, (AFUNPTR)ResetSavedPushes,
			IARG_END
		);
	}
}