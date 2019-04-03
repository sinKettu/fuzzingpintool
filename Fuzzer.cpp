#include <stdio.h>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include "FuzzingPinTool.h"
#include <time.h>
using namespace std;

#define ROUNDS_COUNT 10
#define FUNCTION_ARGUMENTS vector<pair<ADDRINT, UINT32>>

ADDRINT headInsAddr = 0;
ADDRINT tailInsAddr = 0;
CONTEXT backup;
int rouns = ROUNDS_COUNT;


ofstream fout;
BOOL pushDetected = false;
BOOL callDetected = false;
BOOL dontInstrument = false;
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

VOID HandleHead(ADDRINT hAddr, ADDRINT tAddr, CONTEXT *ctxt)
{
	if (headInsAddr != 0)
		return;

	if (dontInstrument)
	{
		dontInstrument = false;
		return;
	}

	PIN_SaveContext(ctxt, &backup);
	headInsAddr = hAddr;
	tailInsAddr = tAddr;
	srand(time(0));
}

VOID HandleTail(ADDRINT addr, ADDRINT next)
{
	if (tailInsAddr != 0 && addr == tailInsAddr)
	{
		if (rouns != 0)
		{
			printf("ROUND: %d\n", ROUNDS_COUNT - rouns + 1);
			CONTEXT tmp;
			PIN_SaveContext(&backup, &tmp);
			rouns--;
			ADDRINT a = PIN_GetContextReg(&tmp, REG_ESP);
			
			*(reinterpret_cast<ADDRINT*>(a + 4)) = rand() & 0xffffffff;
			PIN_ExecuteAt(&tmp);
		}
		else
		{
			headInsAddr = 0;
			tailInsAddr = 0;
			CONTEXT tmp;
			PIN_SaveContext(&backup, &tmp);
			rouns = ROUNDS_COUNT;
			dontInstrument = true;
			PIN_ExecuteAt(&tmp);
		}
	}
}

VOID Fuzzer_Image(IMG img, void*)
{
	if (IMG_IsMainExecutable(img))
	{
		SEC sec = IMG_SecHead(img);
		for (sec; SEC_Valid(sec); sec = SEC_Next(sec))
		{
			if (SEC_Name(sec).compare(".text") == 0)
			{
				RTN rtn = SEC_RtnHead(sec);
				for (rtn; RTN_Valid(rtn); rtn = RTN_Next(rtn))
				{
					if (RTN_Name(rtn).compare("print_test") != 0)
						continue;

					printf("%s\n", RTN_Name(rtn).c_str());
					RTN_Open(rtn);
					INS head = RTN_InsHead(rtn);
					INS next = INS_Next(head);
					INS tail = RTN_InsTail(rtn);
					
					INS_InsertCall(
						head,
						IPOINT_BEFORE, (AFUNPTR)HandleHead,
						IARG_ADDRINT, INS_Address(head),
						IARG_ADDRINT, INS_Address(tail),
						IARG_CONTEXT,
						IARG_END
					);

					INS_InsertCall(
						tail,
						IPOINT_BEFORE, (AFUNPTR)HandleTail,
						IARG_ADDRINT, INS_Address(tail),
						IARG_ADDRINT, INS_Address(next),
						IARG_END
					);

					RTN_Close(rtn);
				}
			}
		}
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
	if (!headInstructions.empty() && headInstructions.back() == addr)
		return;

	CONTEXT tmp;
	PIN_SaveContext(ctxt, &tmp);
	savedContexts.push_back(tmp);
	headInstructions.push_back(addr);
	callDetected = false;

	
}

VOID ResetSavedPushes()
{
	tmp.clear();
	pushDetected = false;
}

VOID HandleRet(const string *name)
{
	if (headInstructions.empty() || savedContexts.empty() || funcArgs.empty())
		return;

	if (name->compare("print_test") == 0)
	{
		printf("\n%s\n", name->c_str());
		printf("[HEAD] 0x%08x\n", headInstructions.back());
		if (!funcArgs.back().empty())
		{
			for (int i = (int)funcArgs.size() - 1; i>=0 ; i--)
			{
				printf("[ARGS]\n");
				ShowFunctionArguments(funcArgs[i]);
				printf("\n");
			}
			
		}
		printf("[CONTEXT]\n");
		ShowContext(&savedContexts.back());
		printf("\n");

		headInstructions.pop_back();
		savedContexts.pop_back();
		funcArgs.pop_back();

	}

	

	/*if (name->compare("print_test") == 0 && rouns != 0)
	{
		ShowFunctionArguments(funcArgs.back());
		CONTEXT tmp;
		PIN_SaveContext(&savedContexts.back(), &tmp);
		PIN_SetContextReg(&tmp, REG_EIP, headInstructions.back());
		rouns--;
		prohibition = true;
		PIN_ExecuteAt(&tmp);
	}
	else
	{
		prohibition = false;
		
	}*/
}

VOID Fuzzer_Instrunction(INS ins, void*)
{
	INS prev = INS_Prev(ins);
	PIN_LockClient();
	IMG img = IMG_FindByAddress(INS_Address(ins));
	PIN_UnlockClient();

	if (!(IMG_Valid(img) && IMG_IsMainExecutable(img)))
		return;

	if (INS_Opcode(ins) == XED_ICLASS_PUSH )
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
	else if (INS_IsRet(ins))
	{
		RTN rtn = RTN_FindByAddress(INS_Address(ins));
		if (RTN_Valid(rtn))
		{
			const string *name = &RTN_Name(rtn);
			INS_InsertCall(
				ins,
				IPOINT_BEFORE, (AFUNPTR)HandleRet,
				IARG_PTR, name,
				IARG_END
			);
		}
		
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