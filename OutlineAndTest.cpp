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
map<ADDRINT, ADDRINT> rangesToTest;
vector<ADDRINT> addressesToSaveContext;

BOOL Fuzzer_LoadList(string path)
{
	ifstream fin;
	fin.open(path.c_str());
	if (!fin.is_open())
		return false;

	routinesToTest.clear();
	string line;
	getline(fin, line);

	bool routinesFlag = false;
	bool rangeFlag = false;
	bool contextFlag = false;

	while (!fin.eof())
	{
		if (!line.compare("[ROUTINES]"))
		{
			routinesFlag = true;
			rangeFlag = false;
			contextFlag = false;
			getline(fin, line);
		}
		else if (!line.compare("[RANGE]"))
		{
			routinesFlag = false;
			rangeFlag = true;
			contextFlag = false;
			getline(fin, line);
		}
		else if (!line.compare("[CONTEXT]"))
		{
			routinesFlag = false;
			rangeFlag = false;
			contextFlag = true;
			getline(fin, line);
		}

		if (routinesFlag)
		{
			if (line[0] != '#' && line.length())
				routinesToTest.push_back(line);
		}
		else if (rangeFlag)
		{
			if (line[0] != '#' && line.length())
			{
				UINT32 first, second;
				char *ptr;
				first = strtoul(line.c_str(), &ptr, 16);
				if (first)
				{
					second = strtoul(ptr, nullptr, 16);
					if (second)
						rangesToTest.insert(make_pair(first, second));
				}
				
			}
		}
		else if (contextFlag)
		{
			if (line[0] != '#' && line.length())
			{
				UINT32 addr = strtoul(line.c_str(), nullptr, 16);
				if (addr)
					addressesToSaveContext.push_back(addr);
			}
		}
		
		getline(fin, line);
	}

	fin.close();
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

VOID Fuzzer_RtnTest(RTN rtn, void*)
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

vector<string> rangeDisasms;
vector<pair<ADDRINT, ADDRINT>> rangeReadings;
CONTEXT rangeHeadCtxt;

VOID ContextHandle(ADDRINT addr, CONTEXT *ctxt)
{
	OatFout.open("outdata.txt", ios::app);
	OatFout << "\n[CONTEXT] " << hexstr(addr) << endl;
	OutputContext(&OatFout, ctxt);
	OatFout.close();
}

VOID RangeHeadHandle(ADDRINT addr, string *dasm, CONTEXT *ctxt)
{
	rangeDisasms.push_back(hexstr(addr) + "\t" + *dasm);
	PIN_SaveContext(ctxt, &rangeHeadCtxt);
}

VOID RangeReadInsHandle(ADDRINT addr, string *dasm, ADDRINT readAddr)
{
	rangeDisasms.push_back(hexstr(addr) + "\t" + *dasm);
	rangeReadings.push_back(make_pair(addr, readAddr));
}

VOID RangeInsHandle(ADDRINT addr, string *dasm)
{
	rangeDisasms.push_back(hexstr(addr) + "\t" + *dasm);
}

VOID RangeTailHandle(ADDRINT head, ADDRINT tail)
{
	OatFout.open("outdata.txt", ios::app);
	OatFout << endl << "[RANGE] " << hexstr(head) << " " << hexstr(tail) << endl;
	OatFout << "[DISASSEMBLED]" << endl;
	for (UINT32 i = 0; i < rangeDisasms.size(); i++)
	{
		OatFout << "\t" << rangeDisasms.at(i) << endl;
	}
	OatFout << endl << "[ENTRY CONTEXT]" << endl;
	OutputContext(&OatFout, &rangeHeadCtxt);
	OatFout << endl << "[READINGS]" << endl;
	for (UINT32 i = 0; i < rangeReadings.size(); i++)
	{
		OatFout << "At " << hexstr(rangeReadings.at(i).first) << " from " << hexstr(rangeReadings.at(i).second) << endl;
	}
	OatFout.close();

	rangeDisasms.clear();
	rangeReadings.clear();
}

map<ADDRINT, ADDRINT>::iterator curRange;
BOOL rangeInProgress = false;

VOID Fuzzer_InsTest(INS ins, void*)
{
	if (!rangesToTest.size() && !addressesToSaveContext.size())
		return;

	UINT32 addr = INS_Address(ins);
	if (find(addressesToSaveContext.begin(), addressesToSaveContext.end(), addr) != addressesToSaveContext.end())
	{
		INS_InsertCall(
			ins,
			IPOINT_BEFORE, (AFUNPTR)ContextHandle,
			IARG_ADDRINT, addr,
			IARG_CONTEXT,
			IARG_END
		);
	}

	if (rangeInProgress)
	{
		if (INS_IsMemoryRead(ins))
		{
			INS_InsertCall(
				ins,
				IPOINT_BEFORE, (AFUNPTR)RangeReadInsHandle,
				IARG_ADDRINT, addr,
				IARG_PTR, new string(INS_Disassemble(ins)),
				IARG_MEMORYREAD_EA,
				IARG_END
			);
		}
		else
		{
			INS_InsertCall(
				ins,
				IPOINT_BEFORE, (AFUNPTR)RangeInsHandle,
				IARG_ADDRINT, addr,
				IARG_PTR, new string(INS_Disassemble(ins)),
				IARG_END
			);
		}

		if (curRange->second == addr)
		{
			INS_InsertCall(
				ins,
				IPOINT_BEFORE, (AFUNPTR)RangeTailHandle,
				IARG_ADDRINT, curRange->first,
				IARG_ADDRINT, curRange->second,
				IARG_END
			);
			rangeInProgress = false;
		}
	}
	else
	{
		curRange = rangesToTest.find(addr);
		if (curRange != rangesToTest.end() && curRange->first == addr)
		{
			rangeInProgress = true;
			INS_InsertCall(
				ins,
				IPOINT_BEFORE, (AFUNPTR)RangeHeadHandle,
				IARG_ADDRINT, addr,
				IARG_PTR, new string(INS_Disassemble(ins)),
				IARG_CONTEXT,
				IARG_END
			);
		}
	}
	
}