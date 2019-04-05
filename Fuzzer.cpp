#include <stdio.h>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include "FuzzingPinTool.h"
#include <time.h>
using namespace std;

#define ROUNDS_COUNT 5
#define ARGUMENTS_COUNT 4
#define DEREFERENCED(x) *(reinterpret_cast<ADDRINT*>(x))

/* GLOBALS */

// Output stream
ofstream fout;

// Fuzzing routine head instruction address
ADDRINT headInsAddr = 0;

// Fuzzing routine tail instruction address
ADDRINT tailInsAddr = 0;

// Routine saved valid context
CONTEXT backup;

// Changed context to run
CONTEXT working;

// used to not instrument last routine execution
BOOL dontInstrument = false;

// Rounds counter
INT32 rounds = ROUNDS_COUNT;

// Saved valid local variables
map<ADDRINT, UINT32> locals_backup;

// Used to not change one local variable twice
vector<ADDRINT> locals;

// Saved routine arguments
map<ADDRINT, UINT32> args;

// Basic block counter
map<ADDRINT, UINT32> traversed;

VOID ShowArguments()
{
	bool flag = false;
	if (!fout.is_open())
	{
		fout.open("outdata.txt", ios::app);
		flag = true;
	}

	for (map<ADDRINT, UINT32>::iterator arg = args.begin(); arg != args.end(); arg++)
	{
		fout << "\t" << hexstr(arg->first) << " --> " << hexstr(arg->second) << endl;
	}

	if (flag)
		fout.close();
}

VOID ShowContext(CONTEXT *ctxt)
{
	bool flag = false;
	if (!fout.is_open())
	{
		fout.open("outdata.txt", ios::app);
		flag = true;
	}

	fout << "\tEAX: " << hexstr(PIN_GetContextReg(ctxt, REG_EAX));
	fout << "\tEBX: " << hexstr(PIN_GetContextReg(ctxt, REG_EBX));
	fout << "\tECX: " << hexstr(PIN_GetContextReg(ctxt, REG_ECX));
	fout << "\tEDX: " << hexstr(PIN_GetContextReg(ctxt, REG_EDX)) << endl;
	fout << "\tESI: " << hexstr(PIN_GetContextReg(ctxt, REG_ESI));
	fout << "\tEDI: " << hexstr(PIN_GetContextReg(ctxt, REG_EDI));
	fout << "\tESP: " << hexstr(PIN_GetContextReg(ctxt, REG_ESP));
	fout << "\tEBP: " << hexstr(PIN_GetContextReg(ctxt, REG_EBP)) << endl;

	if (flag)
		fout.close();
}

VOID ShowTraversedBbl()
{
	if (traversed.empty())
		return;

	bool flag = false;
	if (!fout.is_open())
	{
		fout.open("outdata.txt", ios::app);
		flag = true;
	}

	map<ADDRINT, UINT32>::iterator bbl;
	for (bbl = traversed.begin(); bbl != traversed.end(); bbl++)
	{
		fout << "\t" << hexstr(bbl->first) << ":\t" << bbl->second << endl;
	}

	if (flag)
		fout.close();
}

VOID HandleHead(ADDRINT hAddr, ADDRINT tAddr, CONTEXT *ctxt, const string *name)
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

	fout.open("outdata.txt", ios::app);
	fout << "\n[ROUTINE]\n\t" << *name << endl;
	fout << "[HEAD]\n\t" << hexstr(hAddr) << endl;
	fout << "[TAIL]\n\t" << hexstr(tAddr) << endl;
	fout << "[CONTEXT]\n";
	ShowContext(ctxt);
	fout << "[" << ARGUMENTS_COUNT << " ARGUMENTS]" << endl;
	ShowArguments();
	fout << endl;
	fout.close();
}

VOID HandleTail(ADDRINT addr)
{
	if (addr == tailInsAddr)
	{
		if (rounds != 0)
		{
			PIN_SaveContext(&backup, &working);
			rounds--;
			
			if (!args.empty())
				for (map<ADDRINT, UINT32>::iterator arg = args.begin(); arg != args.end(); arg++)
					DEREFERENCED(arg->first) = (rand() & UINT32_MAX) ^ (rand() & UINT32_MAX);

			fout.open("outdata.txt", ios::app);
			fout << "[ROUND] " << ROUNDS_COUNT - rounds << endl;

			fout << "\tArguments:\n";
			if (!args.empty())
				for (map<ADDRINT, UINT32>::iterator arg = args.begin(); arg != args.end(); arg++)
					fout << "\t" << hexstr(arg->first) << " value set " << hexstr(DEREFERENCED(arg->first)) << endl;
			else
				fout << "\tNone\n";

			fout << "\tLocals:\n";
			if (!locals.empty())
				for (vector<ADDRINT>::iterator local = locals.begin(); local != locals.end(); local++)
					fout << "\t" << hexstr(local) << " value set " << hexstr(DEREFERENCED(local)) << endl;
			else
				fout << "\tNone\n";
			fout.close();

			locals.clear();
			PIN_ExecuteAt(&working);
		}
		else
		{
			headInsAddr = 0;
			tailInsAddr = 0;
			PIN_SaveContext(&backup, &working);

			if (!args.empty())
				for (map<ADDRINT, UINT32>::iterator arg = args.begin(); arg != args.end(); arg++)
					DEREFERENCED(arg->first) = arg->second;

			if (!locals_backup.empty())
				for (map<ADDRINT, UINT32>::iterator local = locals_backup.begin(); local != locals_backup.end(); local++)
					DEREFERENCED(local->first) = local->second;

			fout.open("outdata.txt", ios::app);
			fout << "[BBL]" << endl;
			ShowTraversedBbl();
			fout << endl;
			fout.close();

			traversed.clear();
			locals.clear();
			locals_backup.clear();
			args.clear();
			rounds = ROUNDS_COUNT;
			dontInstrument = true;
			PIN_ExecuteAt(&working);
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
					const string *name = &RTN_Name(rtn);
					if ((name->compare("__scrt_common_main_seh") == 0 || name->compare("__SEH_prolog4") == 0 || name->compare("_IsProcessorFeaturePresent@4") == 0 || name->compare("_should_initialize_environment") == 0 || name->compare("__scrt_acquire_startup_lock") == 0 || name->compare("pre_c_initialization") == 0 || name->compare("__scrt_initialize_onexit_tables") == 0 || name->compare("_initialize_default_precision") == 0))
						continue;

					RTN_Open(rtn);
					INS head = RTN_InsHead(rtn);
					INS tail = RTN_InsTail(rtn);
					
					INS_InsertCall(
						head,
						IPOINT_BEFORE, (AFUNPTR)HandleHead,
						IARG_ADDRINT, INS_Address(head),
						IARG_ADDRINT, INS_Address(tail),
						IARG_CONTEXT,
						IARG_PTR, name,
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

VOID ReplaceLocal(ADDRINT addr)
{
	UINT32 replace = rand() & UINT32_MAX;
	DEREFERENCED(addr) = replace;
}

VOID StackReadHandle(ADDRINT esp, ADDRINT ebp, ADDRINT readAddr, ADDRINT insAddr)
{
	if (insAddr < headInsAddr || insAddr > tailInsAddr)
		return;

	if (!(readAddr >= esp && readAddr < ebp))
		return;

	map<ADDRINT, UINT32>::iterator cell = locals_backup.find(readAddr);
	if (cell == locals_backup.end())
	{
		locals_backup.insert(make_pair(readAddr, DEREFERENCED(readAddr)));
		locals.push_back(readAddr);
		ReplaceLocal(readAddr);
	}
	else
	{
		vector<ADDRINT>::iterator addr = find(locals.begin(), locals.end(), readAddr);
		if (addr == locals.end())
		{
			locals.push_back(readAddr);
			ReplaceLocal(readAddr);
		}
	}
}

VOID Fuzzer_Instrunction(INS ins, void*)
{
	// Make Better Condition!!!
	if (INS_IsMemoryRead(ins))
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

VOID BblHandle(ADDRINT addr)
{
	if (addr < headInsAddr || addr > tailInsAddr)
		return;

	map<ADDRINT, UINT32>::iterator bbl = traversed.find(addr);
	if (bbl == traversed.end())
	{
		traversed.insert(make_pair(addr, 1));
	}
	else
	{
		bbl->second++;
	}
}

VOID Fuzzer_Trace(TRACE trc, void*)
{
	RTN rtn = TRACE_Rtn(trc);
	if (!RTN_Valid(rtn)) return;
	SEC sec = RTN_Sec(rtn);
	IMG img = SEC_Img(sec);
	if (IMG_IsMainExecutable(img))
	{
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
			BBL_InsertCall(
				bbl,
				IPOINT_BEFORE, (AFUNPTR)BblHandle,
				IARG_ADDRINT, INS_Address(BBL_InsHead(bbl)),
				IARG_END
			);
		}
	}
}