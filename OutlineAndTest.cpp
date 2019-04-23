/*  
	Outlines program (list of images with routines)
	And testing any of them (also, addresses ranges 
	and saving instructions contexts)
*/

/*
	TODO: 
		-	Routines tests without first (or any)	(X)
			instructions							(X)
		-	Ranges tests with(out) calls
*/

#pragma once
#include "FuzzingPinTool.h"
using namespace std;

struct InstructionInfo
{
	UINT32 Address;
	string Disassembled;
	UINT32 VisitsCount;
};

ofstream OatFout;

/* G L O B A L S */

/*
 * Used in Outline
 */

map<string, vector<string>> outline;

/*
 * Used in Test
 */

// List of routines for testing in a case
vector<string> routinesToTest;

// Rtn ID -> {addr, disassemblies, visits counts}
map<UINT32, vector<InstructionInfo>> testedRtns;

// Rtn ID -> Rtn Name
map<UINT32, string> rtnsRefs;

// List of addresses ranges [From; To] for testing in a case
map<ADDRINT, ADDRINT> rangesToTest;

// List of addresses which contexts is needed to be saved
vector<ADDRINT> addressesToSaveContext;

// List disassembled instructions in given ranges
vector<string> rangeDisasms;

// List of memory readings in given ranges
vector<pair<ADDRINT, ADDRINT>> rangeReadings;

// Range first visit context
CONTEXT rangeHeadCtxt;

/* R O U T I N E S */

VOID Outline_Image(IMG img, void*)
{
	vector<string> routines;
	string imgName = IMG_Name(img);
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
		{
			RTN_Open(rtn);
			routines.push_back(hexstr(INS_Address(RTN_InsHead(rtn))) + "\t" + RTN_Name(rtn));
			RTN_Close(rtn);
		}
	}

	outline.insert(make_pair(imgName, routines));
}

VOID Outline_Fini(INT32 exitCode, void*)
{
	OatFout.open("outdata.txt", ios::app);
	if (!outline.empty())
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

BOOL Test_LoadList(string path)
{
	ifstream fin;
	fin.open(path.c_str());
	if (!fin.is_open())
		return false;

	routinesToTest.clear();
	string line;

	UINT8 flags = 0;

	while (true)
	{
		getline(fin, line);

		if (!line.compare("[ROUTINES]"))
		{
			flags = 0x01;
			getline(fin, line);
		}
		else if (!line.compare("[RANGE]"))
		{
			flags = 0x02;
			getline(fin, line);
		}
		else if (!line.compare("[CONTEXT]"))
		{
			flags = 0x03;
			getline(fin, line);
		}
		//
		if (flags == 0x01)
		{
			if (line[0] != '#' && line.length())
				routinesToTest.push_back(line);
		}
		else if (flags == 0x02)
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
		else if (flags == 0x03)
		{
			if (line[0] != '#' && line.length())
			{
				UINT32 addr = strtoul(line.c_str(), nullptr, 16);
				if (addr)
					addressesToSaveContext.push_back(addr);
			}
		}
		
		if (fin.eof())
			break;
	}

	fin.close();
	return true;
}

VOID Test_Fini(INT32 exitCode, void*)
{
	OatFout.open("outdata.txt", ios::app);
	for (map<UINT32, vector<InstructionInfo>>::iterator iter = testedRtns.begin(); iter != testedRtns.end(); iter++)
	{
		OatFout << "[ROUTINE] " << rtnsRefs[iter->first] << endl;
		OatFout << "[DISASSEMBLED]\n";
		for (UINT32 i = 0; i < iter->second.size(); i++)
		{
			OatFout << hexstr(iter->second.at(i).Address) << "\t" << iter->second.at(i).Disassembled << " [" << iter->second.at(i).VisitsCount << "]\n";
		}
		OatFout << endl;
	}
	OatFout.close();
}

VOID RtnInsHandler(UINT32 rtnID, UINT32 insID)
{
	testedRtns[rtnID].at(insID).VisitsCount++;
}

VOID Test_Routine(RTN rtn, void*)
{
	if (!RTN_Valid(rtn))
		return;
	
	string name = RTN_Name(rtn);
	if (find(routinesToTest.begin(), routinesToTest.end(), name) == routinesToTest.end())
		return;

	RTN_Open(rtn);

	UINT32 id = RTN_Id(rtn);
	if (testedRtns.find(id) == testedRtns.end())
	{
		rtnsRefs.insert(make_pair(id, name));
		UINT32 counter = 0;
		vector<InstructionInfo> rtnInstructions;
		for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
		{
			InstructionInfo current;
			current.Address = INS_Address(ins);
			current.Disassembled = INS_Disassemble(ins);
			current.VisitsCount = 0;
			rtnInstructions.push_back(current);

			INS_InsertCall(
				ins,
				IPOINT_BEFORE, (AFUNPTR)RtnInsHandler,
				IARG_UINT32, id,
				IARG_UINT32, counter,
				IARG_END
			);

			counter++;
		}

		testedRtns.insert(make_pair(id, rtnInstructions));
	}

	RTN_Close(rtn);
}

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

VOID Test_Instruction(INS ins, void*)
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
