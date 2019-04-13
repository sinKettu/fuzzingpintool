#include <stdio.h>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <time.h>
#include <iostream>
#include "FuzzingPinTool.h"
using namespace std;

#define ROUNDS_COUNT 5
#define ARGUMENTS_COUNT 4
#define DEREFERENCED(x) *(reinterpret_cast<ADDRINT*>(x))
#define EDGE pair<ADDRINT, ADDRINT>

/* GLOBALS */

//
// Used in Fuzzer
//

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

map<EDGE, UINT32> traversed;

// Last visited basic block
ADDRINT lastBbl = 0;

//
// Used in Outline
//

map<string, vector<string>> outline;

////
// Used in Test
////

// Context of first instruction
CONTEXT enterContext;

// Address of head instruction
ADDRINT head = 0;

// Address of tail instruction
ADDRINT tail = 0;

// Value of EAX in the tail
UINT32 eaxExitVal;

// Routine name
string rName;

// Saved info about readings from memory
vector<pair<ADDRINT, ADDRINT>> readings;

// Addresses of disassembled instructions
vector<ADDRINT> insAdresses;

// Disasm-d instructions
vector<string> insDisasms;

// Saved enties to routines from 'routinesToTest'
vector<CONTEXT> calls;

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

	for (map<EDGE, UINT32>::iterator edge = traversed.begin(); edge != traversed.end(); edge++)
	{
		fout << "\t(" << hexstr(edge->first.first) << ")->(" << hexstr(edge->first.second) << "):\t" << edge->second << endl;
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
					fout << "\t" << hexstr(*local) << " value set " << hexstr(DEREFERENCED(*local)) << endl;
			else
				fout << "\tNone\n";
			fout.close();

			lastBbl = 0;
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
			fout << "[BBL EDGES]" << endl;
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

VOID BblHandle(ADDRINT addr, ADDRINT prevAddr)
{
	if (addr < headInsAddr || addr > tailInsAddr)
		return;

	if (lastBbl != 0)
	{
		EDGE tmp = make_pair(lastBbl, addr);
		lastBbl = addr;

		map<EDGE, UINT32>::iterator it = traversed.find(tmp);
		if (it == traversed.end())
			traversed.insert(make_pair(tmp, 1));
		else
			it->second++;
	}
	else
		lastBbl = addr;
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
			BBL prev = BBL_Prev(bbl);
			BBL_InsertCall(
				bbl,
				IPOINT_BEFORE, (AFUNPTR)BblHandle,
				IARG_ADDRINT, INS_Address(BBL_InsHead(bbl)),
				IARG_END
			);
		}
	}
}

VOID Fuzzer_Outline(IMG img, void*)
{
	vector<string> routines;
	string imgName = IMG_Name(img);
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		if (SEC_Name(sec).compare(".text"))
			continue;

		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
		{
			routines.push_back(RTN_Name(rtn));
		}
	}

	outline.insert(make_pair(imgName, routines));
}

VOID Fuzzer_OutlineOutput(INT32 exitCode, void*)
{
	fout.open("outdata.txt");
	for (map<string, vector<string>>::iterator image = outline.begin(); image != outline.end(); image++)
	{
		fout << image->first << endl;
		for (UINT32 i = 0; i < image->second.size(); i++)
		{
			fout << "\t" << image->second.at(i) << endl;
		}
		image->second.clear();
	}
	fout.close();
}

vector<string> routinesToTest;

BOOL Fuzzer_LoadList(string path)
{
	ifstream fin;
	fin.open(path.c_str());
	if (!fin.is_open())
		return false;

	routinesToTest.clear();
	while (!fin.eof())
	{
		string tmp;
		getline(fin, tmp);
		routinesToTest.push_back(tmp);
		cout << tmp << endl;
	}

	return true;
}

VOID OutpitTestInfo()
{
	fout.open("outdata.txt", ios::app);
	fout << "[NAME] " << rName << endl;
	fout << endl << "[DISASSEMBLED]" << endl;
	for (UINT32 i = 0; i < insAdresses.size(); i++)
	{
		fout << hexstr(insAdresses.at(i)) << "\t" << insDisasms.at(i) << endl;
	}
	fout << endl;
	fout << endl << "[ENTER CONTEXT]" << endl;
	ShowContext(&enterContext);
	fout << endl << "[EXIT EAX] " << hexstr(eaxExitVal) << endl;
	fout << "[MEMORY READINGS]" << endl;
	for (UINT32 i = 0; i < readings.size(); i++)
	{
		fout << "At " << hexstr(readings.at(i).first) << " from " << hexstr(readings.at(i).second) << endl;
	}
	fout << endl;
	fout.close();
}

VOID InsHeadHandler(ADDRINT hAddr, ADDRINT tAddr, string* name, CONTEXT *ctxt)
{
	if (head != 0 && tail != 0)
	{
		CONTEXT tmp;
		PIN_SaveContext(ctxt, &tmp);
		calls.push_back(tmp);
		return;
	}

	head = hAddr;
	tail = tAddr;
	rName = *name;
	PIN_SaveContext(ctxt, &enterContext);
}

VOID InsTailHandler(ADDRINT addr, ADDRINT eax)
{
	if (addr == tail)
	{
		eaxExitVal = eax;
		OutpitTestInfo();

		head = 0;
		tail = 0;
		rName = "";
		eaxExitVal = 0;
		readings.clear();
		insAdresses.clear();
		insDisasms.clear();

		if (!calls.empty())
		{
			CONTEXT next = calls.back();
			calls.pop_back();

			PIN_ExecuteAt(&next);
		}
	}
}

VOID InsMemReadHandler(ADDRINT insAddr, ADDRINT rdAddr)
{
	if (insAddr >= head && insAddr <= tail)
	{
		readings.push_back(make_pair(insAddr, rdAddr));
	}
}

VOID InsHandler(ADDRINT addr, string *dasm)
{
	if (addr >= head && addr <= tail)
	{
		insAdresses.push_back(addr);
		insDisasms.push_back(*dasm);
	}
}

VOID Fuzzer_Test(RTN rtn, void*)
{
	string *rtnName = const_cast<string *>(&RTN_Name(rtn));
	if (find(routinesToTest.begin(), routinesToTest.end(), *rtnName) != routinesToTest.end())
	{
		RTN_Open(rtn);

		INS head = RTN_InsHead(rtn);
		INS tail = RTN_InsTail(rtn);

		INS_InsertCall(
			head,
			IPOINT_BEFORE, (AFUNPTR)InsHeadHandler,
			IARG_ADDRINT, INS_Address(head),
			IARG_ADDRINT, INS_Address(tail),
			IARG_PTR, rtnName,
			IARG_CONTEXT,
			IARG_END
		);

		INS_InsertCall(
			tail,
			IPOINT_BEFORE, (AFUNPTR)InsTailHandler,
			IARG_ADDRINT, INS_Address(tail),
			IARG_REG_VALUE, REG_EAX,
			IARG_END
		);

		
		for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
		{

			if (INS_IsMemoryRead(ins))
			{
				INS_InsertCall(
					ins,
					IPOINT_BEFORE, (AFUNPTR)InsMemReadHandler,
					IARG_ADDRINT, INS_Address(ins),
					IARG_MEMORYREAD_EA,
					IARG_END
				);
			}

			INS_InsertCall(
				ins,
				IPOINT_BEFORE, (AFUNPTR)InsHandler,
				IARG_ADDRINT, INS_Address(ins),
				IARG_PTR, new string(INS_Disassemble(ins)),
				IARG_END
			);

		}

		RTN_Close(rtn);
	}
}