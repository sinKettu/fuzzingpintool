/* Tracking data in memory */

#include "FuzzingPinTool.h"
using namespace std;

typedef map<UINT8, vector<string>> FoundChars;
typedef map<string, vector<string>> FoundStrings;

ofstream TrackerFout;

vector<UINT8> charsToTrack;
vector<string> charsImgs;

vector<UINT16> shortsToTrack;
vector<UINT32> intsToTrack;

vector<string> stringsToTrack;
vector<string> stringImgs;

FoundChars foundChars;
FoundStrings foundStrings;

VOID ParseCharArgs(string line, string &imgName, UINT8 &val)
{
	UINT32 i = 0;
	for (; i < line.length() && line[i] != ' '; i++) {}
	if (i == line.length())
	{
		val = 0;
		return;
	}

	imgName = line.substr(0, i);
	UINT32 tmp = strtoul(line.c_str() + i, nullptr, 16);
	if (tmp > 0xff)
	{
		val = 0;
		return;
	}

	val = static_cast<UINT8>(tmp);
}

VOID ParseStringArgs(string line, string &imgName, string &str)
{
	UINT32 i = 0;
	if (line[0] == '"')
	{
		i++;
		for (; i < line.length() && line[i] != '"'; i++) {}
		if (i == line.length())
		{
			str = "";
			return;
		}
		imgName = line.substr(1, i);
		str = line.substr(i + 2, line.length());
	}
	else
	{
		for (; i < line.length() && line[i] != ' '; i++) {}
		if (i == line.length())
		{
			str = "";
			return;
		}

		imgName = line.substr(0, i);
		str = line.substr(i + 1, line.length());
	}
	
}

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
	while (true)
	{
		getline(fin, line);
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
				string imgName = "";
				UINT8 val = 0;
				ParseCharArgs(line, imgName, val);
				if (val)
				{
					charsToTrack.push_back(val);
					charsImgs.push_back(imgName);
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
			{
				string imgName = "", str = "";
				ParseStringArgs(line, imgName, str);
				if (str.length())
				{
					stringsToTrack.push_back(str);
					stringImgs.push_back(imgName);
				}
			}
		}

		if (fin.eof())
			break;
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
	if (!foundStrings.empty())
	{
		for (FoundStrings::iterator iter = foundStrings.begin(); iter != foundStrings.end(); iter++)
		{
			TrackerFout << endl << "[STRING] " << iter->first << endl;
			for (vector<string>::iterator one = iter->second.begin(); one != iter->second.end(); one++)
			{
				TrackerFout << *one << endl;
			}
		}
	}
	TrackerFout.close();
}

VOID ReadCharHandle(ADDRINT rAddr, ADDRINT insAddr, string* rtnName, string* disasm, string *imgName)
{
	UINT8 val = static_cast<UINT8>(DEREFERENCED(rAddr));
	vector<UINT8>::iterator veci = find(charsToTrack.begin(), charsToTrack.end(), val);
	if (veci != charsToTrack.end() && !charsImgs[veci - charsToTrack.begin()].compare(*imgName))
	{
		FoundChars::iterator iter = foundChars.find(val);
		string tmpStr = *rtnName + " : " + hexstr(insAddr) + " : " + *disasm;
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

// unknown problem!
VOID ReadStrHandle(ADDRINT rAddr, ADDRINT insAddr, string *name, string *disasm, string *imgName)
{
	ADDRINT *base = reinterpret_cast<ADDRINT *>(DEREFERENCED(rAddr));
	char *c;
	for (vector<string>::iterator str = stringsToTrack.begin(); str != stringsToTrack.end(); str++)
	{
		c = new char[str->length()];
		memset(c, 0, str->length());
		PIN_SafeCopy(c, base, str->length());
		if (*c == 0)
		{
			delete[] c;
			return;
		}

		if (strlen(c) == str->length() && 
			!str->compare(c) && 
			!stringImgs[str - stringsToTrack.begin()].compare(*imgName))
		{
			FoundStrings::iterator iter = foundStrings.find(*str);
			string tmpStr = *name + " : " + hexstr(insAddr) + " : " + *disasm;
			if (iter == foundStrings.end())
			{
				vector<string> tmpVec;
				tmpVec.push_back(tmpStr);

				foundStrings.insert(make_pair(*str, tmpVec));
			}
			else
			{
				iter->second.push_back(tmpStr);
			}

			delete[] c;
			return;
		}
		else
			delete[] c;

	}
}

VOID Tracker_Instruction(INS ins, void*)
{
	if (!charsToTrack.empty() &&  INS_IsMemoryRead(ins) && INS_MemoryReadSize(ins) == 1)
	{
		RTN rtn = INS_Rtn(ins);
		if (RTN_Valid(rtn))
		{
			string *imgName = const_cast<string*>(
				&IMG_Name(
					SEC_Img(
						RTN_Sec(rtn)
					)
				)
				);

			if (find(charsImgs.begin(), charsImgs.end(), *imgName) == charsImgs.end())
				return;

			string *name = const_cast<string*>(&RTN_Name(rtn));
			INS_InsertCall(
				ins,
				IPOINT_BEFORE, (AFUNPTR)ReadCharHandle,
				IARG_MEMORYREAD_EA,
				IARG_ADDRINT, INS_Address(ins),
				IARG_PTR, name,
				IARG_PTR, new string(INS_Disassemble(ins)),
				IARG_PTR, imgName,
				IARG_END
			);
		}
	}
	if (!stringsToTrack.empty() && INS_IsMemoryRead(ins))
	{
		RTN rtn = INS_Rtn(ins);
		if (RTN_Valid(rtn))
		{
			string *imgName = const_cast<string*>(
				&IMG_Name(
					SEC_Img(
						RTN_Sec(rtn)
					)
				)
				);

			if (find(stringImgs.begin(), stringImgs.end(), *imgName) == stringImgs.end())
				return;

			string *name = const_cast<string*>(&RTN_Name(rtn));
			INS_InsertCall(
				ins,
				IPOINT_BEFORE, (AFUNPTR)ReadStrHandle,
				IARG_MEMORYREAD_EA,
				IARG_ADDRINT, INS_Address(ins),
				IARG_PTR, name,
				IARG_PTR, new string(INS_Disassemble(ins)),
				IARG_PTR, imgName,
				IARG_END
			);
		}
	}
}