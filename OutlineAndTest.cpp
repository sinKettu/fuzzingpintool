/*  
	Outlines program (list of images with routines)
	And testing any of them (also, addresses ranges 
	and saving instructions contexts)
*/

/*
	TODO: 
		-	Routines tests without first (or any)	(X)
			instructions							(X)
		-	Ranges tests							(X)
*/

#pragma once
#include "FuzzingPinTool.h"
using namespace std;

typedef map<ADDRINT, pair<INT32, UINT8>> ReadData;

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

// Count of ranges in progress
UINT32 rangesCounter = 0;

// Traversed instructions
vector<InstructionInfo> insInRanges;

ReadData toRead;

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

VOID ParseRead(string line, ADDRINT &insAddr, INT32 &readAddr, UINT8 &reg)
{
	UINT32 i = 0;
	char *regsNames[] = { "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp" };
	for (; i < line.length() && line[i] != ' '; i++){}
	if (i < line.length())
	{
		string tmp = line.substr(0, i);
		insAddr = strtoul(tmp.c_str(), nullptr, 16);
		if (insAddr == 0)
			return;

		i++;
		tmp = line.substr(i, 3);
		UINT32 j = 0;
		for (; j < 8 && strcmp(regsNames[j], tmp.c_str()); j++){}
		if (j < 8)
		{
			i += 3;
			if (line[i] == '-')
			{
				i++;
				reg = 1 << j;
				tmp = line.substr(i, line.size());
				readAddr = 0 - strtol(tmp.c_str(), nullptr, 16);
				if (!readAddr)
				{
					insAddr = 0;
					readAddr = 0;
				}
			}
			else if (line[i] == '+')
			{
				i++;
				reg = 1 << j;
				tmp = line.substr(i, line.size());
				readAddr = strtol(tmp.c_str(), nullptr, 16);
				if (!readAddr)
				{
					insAddr = 0;
					readAddr = 0;
				}
			}
			else
			{
				reg = 0xff;
				insAddr = 0;
				readAddr = 0;
			}
		}
		else
		{
			reg = false;
			readAddr = static_cast<INT32>(strtoul(line.c_str() + i, nullptr, 16));
			if (!readAddr)
			{
				insAddr = 0;
				readAddr = 0;
			}
		}
	}
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
		else if (!line.compare("[READ]"))
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
			ADDRINT insAddr = 0; 
			INT32 readAddr = 0;
			UINT8 reg = false;
			ParseRead(line, insAddr, readAddr, reg);
			if (readAddr && insAddr)
			{
				toRead.insert(make_pair(insAddr, make_pair(readAddr, reg)));
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
	for (map<ADDRINT, ADDRINT>::iterator iter = rangesToTest.begin(); iter != rangesToTest.end(); iter++)
	{
		OatFout << "[RANGE] " << hexstr(iter->first) << ": " << hexstr(iter->second) << endl;
		OatFout << "[DISASSEMBLED]" << endl;
		for (UINT32 i = 0; i < insInRanges.size(); i++)
		{
			if (insInRanges.at(i).Address >= iter->first && insInRanges.at(i).Address <= iter->second)
			{
				OatFout << hexstr(insInRanges.at(i).Address) << "\t" << insInRanges.at(i).Disassembled << "\t[" << insInRanges.at(i).VisitsCount << "]\n";
			}
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

VOID RangeInsHandler(UINT32 insID)
{
	insInRanges[insID].VisitsCount++;
}

VOID Test_Instruction(INS ins, void*)
{
	ADDRINT addr = INS_Address(ins);

	// Range part

	if (rangesCounter)
	{
		InstructionInfo insInfo;
		insInfo.Address = addr;
		insInfo.Disassembled = INS_Disassemble(ins);
		insInfo.VisitsCount = 0;
		insInRanges.push_back(insInfo);

		INS_InsertCall(
			ins,
			IPOINT_BEFORE, (AFUNPTR)RangeInsHandler,
			IARG_UINT32, insInRanges.size() - 1,
			IARG_END
		);
	}

	for (map<ADDRINT, ADDRINT>::iterator iter = rangesToTest.begin(); iter != rangesToTest.end(); iter++)
	{
		if (iter->first == addr)
			rangesCounter++;

		if (rangesCounter && iter->second == addr)
			rangesCounter--;
	}

	// Read part

	ReadData::iterator iter = toRead.find(addr);
	if (iter != toRead.end())
	{
		UINT8 reg = iter->second.second;
		INT32 readAddr = iter->second.first;
		if (reg == 0xff)
		{
			INS_InsertCall(
				ins,
				IPOINT_BEFORE, (AFUNPTR)ReadFromMemoryHandler,
				IARG_ADDRINT, addr,
				IARG_ADDRINT, (ADDRINT)readAddr,
				IARG_END
			);
		}
		else
		{

		}
	}
}