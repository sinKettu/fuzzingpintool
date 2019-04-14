#pragma once
#include "FuzzingPinTool.h"
using namespace std;

ofstream OatFout;

/*
 * Used in Outline
 */

map<string, vector<string>> outline;

/*
 * Used in Test
 */

// Routine name
string rName;

// Saved info about readings from memory
vector<vector<pair<ADDRINT, ADDRINT>>> readings;

// listings of disassembled stack
vector<map<ADDRINT, string>> disasms;

// Enrty contexts stack
vector<CONTEXT> contexts;

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
			RTN_Open(rtn);
			routines.push_back(hexstr(INS_Address(RTN_InsHead(rtn))) + "\t" + RTN_Name(rtn));
			RTN_Close(rtn);
		}
	}

	outline.insert(make_pair(imgName, routines));
}

VOID Fuzzer_OutlineOutput(INT32 exitCode, void*)
{
	OatFout.open("outdata.txt");
	for (map<string, vector<string>>::iterator image = outline.begin(); image != outline.end(); image++)
	{
		OatFout << image->first << endl;
		for (UINT32 i = 0; i < image->second.size(); i++)
		{
			OatFout << "\t" << image->second.at(i) << endl;
		}
		image->second.clear();
	}
	OatFout.close();
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
	}

	return true;
}

VOID OutputTestInfo(
	string name,
	CONTEXT *ctxt,
	map<ADDRINT, string> curDisasms,
	vector<pair<ADDRINT, ADDRINT>> curReads,
	UINT32 eax)
{
	OatFout.open("outdata.txt", ios::app);
	OatFout << "[NAME] " << name << endl;
	OatFout << endl << "[DISASSEMBLED]" << endl;
	for (map<ADDRINT, string>::iterator line = curDisasms.begin(); line != curDisasms.end(); line++)
	{
		OatFout << hexstr(line->first) << "\t" << line->second << endl;
	}
	OatFout << endl;
	OatFout << endl << "[ENTER CONTEXT]" << endl;
	OutputContext(&OatFout, ctxt);
	OatFout << endl << "[EXIT EAX] " << hexstr(eax) << endl;
	OatFout << "[MEMORY READINGS]" << endl;
	for (UINT32 i = 0; i < curReads.size(); i++)
	{
		OatFout << "At " << hexstr(curReads.at(i).first) << " from " << hexstr(curReads.at(i).second) << endl;
	}
	OatFout << endl;
	OatFout.close();
}

VOID InsHeadHandler(CONTEXT *ctxt)
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
	OutputTestInfo(
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