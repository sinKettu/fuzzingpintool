/* Tracking data in memory */

#include "FuzzingPinTool.h"
using namespace std;

typedef map<UINT8, vector<string>> FoundChars;
typedef map<string, vector<string>> FoundStrings;

/* G L O B A L S */

ofstream TrackerFout;

// What chars in what images search
vector<UINT8> charsToTrack;
vector<string> charsImgs;

// What shorts in what images search (not released)
vector<UINT16> shortsToTrack;
vector<string> shortsImgs;

// What integers in what images search (not released)
vector<UINT32> intsToTrack;
vector<string> intsImages;

// What strings in what images search
vector<string> stringsToTrack;
vector<string> stringImgs;

// What chars in what instructions found
FoundChars foundChars;

// What strings in what instructions found
FoundStrings foundStrings;

// Max string to search length
UINT32 maxStrLength = 0;

/* R O U T I N E S */

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

	UINT8 flags = 0;

	string line;
	while (true)
	{
		getline(fin, line);
		if (!line.compare("[1]"))
		{
			flags = 0x01;
			getline(fin, line);
		}
		else if (!line.compare("[2]"))
		{
			flags = 0x02;
			getline(fin, line);
		}
		else if (!line.compare("[4]"))
		{
			flags = 0x03;
			getline(fin, line);
		}
		else if (!line.compare("[c]"))
		{
			flags = 0x04;
			getline(fin, line);
		}

		if (flags == 0x01)
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
		else if (flags == 0x02)
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
		else if (flags == 0x03)
		{
			if (line[0] != '#' && line.length())
			{
				UINT32 tmp = strtoul(line.c_str(), nullptr, 16);
				if (tmp)
					intsToTrack.push_back(tmp);
			}
		}
		else if (flags == 0x04)
		{
			if (line[0] != '#' && line.length())
			{
				string imgName = "", str = "";
				ParseStringArgs(line, imgName, str);
				if (str.length() && str.length() < 2048)
				{
					stringsToTrack.push_back(str);
					stringImgs.push_back(imgName);
					maxStrLength = max(maxStrLength, str.length());
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

	// ???
	delete disasm;
}

VOID ReadStrHandle(ADDRINT rAddr, ADDRINT insAddr, string *name, string *disasm, string *imgName)
{
	ADDRINT rrAddr = 0;
	PIN_SafeCopy(&rrAddr, reinterpret_cast<ADDRINT*>(rAddr), 4);
	if (!rrAddr)
		return;

	ADDRINT *base = reinterpret_cast<ADDRINT *>(rrAddr);
	char *c = new char[maxStrLength];
	for (vector<string>::iterator str = stringsToTrack.begin(); str != stringsToTrack.end(); str++)
	{
		memset(c, 0, maxStrLength);
		PIN_SafeCopy(c, base, str->length());
		if (*c == 0)
		{
			delete[] c;
			delete disasm;
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
			delete disasm;
			return;
		}

	}

	delete[] c;
	delete disasm;
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
	if (!stringsToTrack.empty() && INS_IsMemoryRead(ins) && INS_MemoryReadSize(ins) == 4)
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
				IARG_PTR,	  name,
				IARG_PTR,	  new string(INS_Disassemble(ins)),
				IARG_PTR,	  imgName,
				IARG_END
			);
		}
	}
}