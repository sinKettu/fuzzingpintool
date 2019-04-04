#include <stdio.h>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include "FuzzingPinTool.h"
#include <time.h>
using namespace std;

#define ROUNDS_COUNT 10
#define ARGUMENTS_COUNT 4
#define DEREFERENCED(x) *(reinterpret_cast<ADDRINT*>(x))

ofstream fout;
ADDRINT headInsAddr = 0;
ADDRINT tailInsAddr = 0;
CONTEXT backup;
BOOL dontInstrument = false;
INT32 rounds = ROUNDS_COUNT;
map<ADDRINT, UINT32> locals;
map<ADDRINT, UINT32> args;

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

VOID HandleHead(ADDRINT hAddr, ADDRINT tAddr, CONTEXT *ctxt)
{
	if (headInsAddr != 0)
		return;

	if (dontInstrument)
	{
		dontInstrument = false;
		return;
	}

	ADDRINT esp = PIN_GetContextReg(ctxt, REG_ESP);
	for (UINT32 arg = 4; arg < ARGUMENTS_COUNT * 4 + 4; arg += 4)
		args.insert(make_pair(esp + arg, DEREFERENCED(esp + arg)));

	PIN_SaveContext(ctxt, &backup);
	headInsAddr = hAddr;
	tailInsAddr = tAddr;
	srand(time(0));
}

VOID HandleTail(ADDRINT addr)
{
	if (addr == tailInsAddr)
	{
		if (rounds != 0)
		{
			printf("_ROUND: %d\n", ROUNDS_COUNT - rounds + 1);
			CONTEXT tmp;
			PIN_SaveContext(&backup, &tmp);
			rounds--;
			
			if (!args.empty())
				for (map<ADDRINT, UINT32>::iterator arg = args.begin(); arg != args.end(); arg++)
					DEREFERENCED(arg->first) = rand() & UINT32_MAX;

			if (!locals.empty())
				for (map<ADDRINT, UINT32>::iterator local = locals.begin(); local != locals.end(); local++)
					DEREFERENCED(local->first) = rand() & UINT32_MAX;

			PIN_ExecuteAt(&tmp);
		}
		else
		{
			headInsAddr = 0;
			tailInsAddr = 0;
			CONTEXT tmp;
			PIN_SaveContext(&backup, &tmp);

			if (!args.empty())
				for (map<ADDRINT, UINT32>::iterator arg = args.begin(); arg != args.end(); arg++)
					DEREFERENCED(arg->first) = arg->second;

			if (!locals.empty())
				for (map<ADDRINT, UINT32>::iterator local = locals.begin(); local != locals.end(); local++)
					DEREFERENCED(local->first) = local->second;

			locals.clear();
			args.clear();
			rounds = ROUNDS_COUNT;
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
						IARG_END
					);

					RTN_Close(rtn);
				}
			}
		}
	}
}

VOID StackReadHandle(ADDRINT esp, ADDRINT ebp, ADDRINT readAddr, ADDRINT insAddr)
{
	if (insAddr < headInsAddr || insAddr > tailInsAddr)
		return;

	if (!(readAddr >= esp && readAddr < ebp))
		return;

	map<ADDRINT, UINT32>::iterator cell = locals.find(readAddr);
	if (cell == locals.end())
	{
		locals.insert(make_pair(readAddr, DEREFERENCED(readAddr)));
		printf("local 0x%08x is 0x%08x\n", readAddr, DEREFERENCED(readAddr));
	}
}

VOID Fuzzer_Instrunction(INS ins, void*)
{
	// Make Better Condition!!!
	if (INS_IsMemoryRead(ins)/* && INS_MemoryOperandCount(ins) == 2/* && INS_MemoryOperandIsRead(ins, 1)*/)
	{
		INS_InsertCall(
			ins,
			IPOINT_BEFORE, (AFUNPTR)StackReadHandle,
			IARG_REG_VALUE, REG_ESP,
			IARG_REG_VALUE, REG_EBP,
			IARG_MEMORYREAD_EA,
			IARG_ADDRINT, INS_Address(ins),
			IARG_END
		);
	}
}