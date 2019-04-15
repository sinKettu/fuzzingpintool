/* Tracking data in memory */

#include "FuzzingPinTool.h"
using namespace std;

typedef map<UINT8, vector<string>> FoundChars;

ofstream TrackerFout;

vector<UINT8> charsToTrack;
vector<UINT16> shortsToTrack;
vector<UINT32> intsToTrack;
vector<string> stringsToTrack;

FoundChars foundChars;

BOOL Tracker_LoadList(string path)
{
	ifstream fin;
	fin.open(path.c_str());
	if (!fin.is_open())
		return false;

	bool ch = false;
	bool sh = false;
	bool in = false;
	bool st = false;

	string line;
	getline(fin, line);
	while (!fin.eof())
	{
		if (!line.compare("[1]"))
		{
			ch = true;
			sh = false;
			in = false;
			st = false;
			getline(fin, line);
		}
		else if (!line.compare("[2]"))
		{
			ch = false;
			sh = true;
			in = false;
			st = false;
			getline(fin, line);
		}
		else if (!line.compare("[4]"))
		{
			ch = false;
			sh = false;
			in = true;
			st = false;
			getline(fin, line);
		}
		else if (!line.compare("[c]"))
		{
			ch = false;
			sh = false;
			in = false;
			st = true;
			getline(fin, line);
		}

		if (ch)
		{
			if (line[0] != '#' && line.length())
			{
				UINT32 tmp = strtoul(line.c_str(), nullptr, 16);
				if (tmp && tmp <= 0xff)
				{
					UINT8 c = static_cast<UINT8>(tmp);
					charsToTrack.push_back(c);
				}
			}
		}
		else if (sh)
		{
			if (line[0] != '#' && line.length())
			{
				UINT32 tmp = strtoul(line.c_str(), nullptr, 16);
				if (tmp && tmp <= 0xffff)
				{
					UINT16 s = static_cast<UINT16>(tmp);
					shortsToTrack.push_back(s);
				}
			}
		}
		else if (in)
		{
			if (line[0] != '#' && line.length())
			{
				UINT32 tmp = strtoul(line.c_str(), nullptr, 16);
				if (tmp)
					intsToTrack.push_back(tmp);
			}
		}
		else if (st)
		{
			if (line[0] != '#' && line.length())
				stringsToTrack.push_back(line);
		}

		getline(fin, line);
	}

	fin.close();
	return true;
}

VOID Tracker_Fini(INT32 exitCode, void*)
{
	TrackerFout.open("outdata.txt", ios::app);
	if (!foundChars.empty())
	{
		for (FoundChars::iterator iter = foundChars.begin(); iter != foundChars.end(); iter++)
		{
			TrackerFout << endl << "[CHAR] " << hexstr(iter->first) << endl;
			for (vector<string>::iterator one = iter->second.begin(); one != iter->second.end(); one++)
			{
				TrackerFout << *one << endl;
			}
		}
	}
	TrackerFout.close();
}

VOID ReadCharHandle(ADDRINT rAddr, ADDRINT insAddr, string* rtnName, string* disasm)
{
	UINT8 val = static_cast<UINT8>(DEREFERENCED(rAddr));
	if (find(charsToTrack.begin(), charsToTrack.end(), val) != charsToTrack.end())
	{
		FoundChars::iterator iter = foundChars.find(val);
		string tmpStr = *rtnName + "\t\t:\t" + hexstr(insAddr) + "\t:\t" + *disasm;
		if (iter == foundChars.end())
		{
			vector<string> tmpVec;
			tmpVec.push_back(tmpStr);

			foundChars.insert(make_pair(val, tmpVec));
		}
		else
		{
			iter->second.push_back(tmpStr);
		}
	}
}

VOID Tracker_Instruction(INS ins, void*)
{
	if (!charsToTrack.empty() && INS_IsMemoryRead(ins) && INS_MemoryReadSize(ins) == 1)
	{
		RTN rtn = INS_Rtn(ins);
		string *name = const_cast<string*>(&RTN_Name(rtn));
		INS_InsertCall(
			ins,
			IPOINT_BEFORE, (AFUNPTR)ReadCharHandle,
			IARG_MEMORYREAD_EA,
			IARG_ADDRINT, INS_Address(ins),
			IARG_PTR, name,
			IARG_PTR, new string(INS_Disassemble(ins)),
			IARG_END
		);
	}
}