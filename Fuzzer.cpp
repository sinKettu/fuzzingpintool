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

////
// Used in Fuzzer
////

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

////
// Used in Outline
////

map<string, vector<string>> outline;

////
// Used in Test
////

// Routine name
string rName;

// Saved info about readings from memory
vector<vector<pair<ADDRINT, ADDRINT>>> readings;

// listings of disassembled stack
vector<map<ADDRINT, string>> disasms;
//vector<vector<ADDRINT>> addresses;
//vector<vector<string>> disasms;

// Enrty contexts stack
vector<CONTEXT> contexts;

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

	fout << "EAX: " << hexstr(PIN_GetContextReg(ctxt, REG_EAX)) << endl;
	fout << "EBX: " << hexstr(PIN_GetContextReg(ctxt, REG_EBX)) << endl;
	fout << "ECX: " << hexstr(PIN_GetContextReg(ctxt, REG_ECX)) << endl;
	fout << "EDX: " << hexstr(PIN_GetContextReg(ctxt, REG_EDX)) << endl;
	fout << "ESI: " << hexstr(PIN_GetContextReg(ctxt, REG_ESI)) << endl;
	fout << "EDI: " << hexstr(PIN_GetContextReg(ctxt, REG_EDI)) << endl;
	fout << "ESP: " << hexstr(PIN_GetContextReg(ctxt, REG_ESP)) << endl;
	fout << "EBP: " << hexstr(PIN_GetContextReg(ctxt, REG_EBP)) << endl;

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

VOID OutpitTestInfo(
	string name, 
	CONTEXT *ctxt, 
	map<ADDRINT, string> curDisasms, 
	vector<pair<ADDRINT, ADDRINT>> curReads, 
	UINT32 eax)
{
	fout.open("outdata.txt", ios::app);
	fout << "[NAME] " << name << endl;
	fout << endl << "[DISASSEMBLED]" << endl;
	for (map<ADDRINT, string>::iterator line = curDisasms.begin(); line != curDisasms.end(); line++)
	{
		fout << hexstr(line->first) << "\t" << line->second << endl;
	}
	fout << endl;
	fout << endl << "[ENTER CONTEXT]" << endl;
	ShowContext(ctxt);
	fout << endl << "[EXIT EAX] " << hexstr(eax) << endl;
	fout << "[MEMORY READINGS]" << endl;
	for (UINT32 i = 0; i < curReads.size(); i++)
	{
		fout << "At " << hexstr(curReads.at(i).first) << " from " << hexstr(curReads.at(i).second) << endl;
	}
	fout << endl;
	fout.close();
}



VOID InsHeadHandler(ADDRINT hAddr, ADDRINT tAddr, string* name, CONTEXT *ctxt)
{
	map<ADDRINT, string> tmpDs;
	tmpDs.clear();
	disasms.push_back(tmpDs);
	
	CONTEXT tmp;
	PIN_SaveContext(ctxt, &tmp);
	contexts.push_back(tmp);

	vector<pair<ADDRINT, ADDRINT>> tmpReads;
	tmpReads.clear();
	readings.push_back(tmpReads);
}

VOID InsTailHandler(ADDRINT addr, ADDRINT eax, string *rtnName)
{
	OutpitTestInfo(
		*rtnName, 
		&contexts.back(), 
		disasms.back(),
		readings.back(),
		eax
	);

	contexts.pop_back();
	disasms.pop_back();
	readings.pop_back();
}

VOID InsMemReadHandler(ADDRINT insAddr, ADDRINT rdAddr)
{
	readings.back().push_back(make_pair(insAddr, rdAddr));
}

VOID InsHandler(ADDRINT addr, string *dasm)
{
	disasms.back().insert(make_pair(addr, *dasm));
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

		INS_InsertCall(
			tail,
			IPOINT_BEFORE, (AFUNPTR)InsTailHandler,
			IARG_ADDRINT, INS_Address(tail),
			IARG_REG_VALUE, REG_EAX,
			IARG_PTR, rtnName,
			IARG_END
		);

		RTN_Close(rtn);
	}

}