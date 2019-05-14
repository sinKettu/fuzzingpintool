/*  
	Outlines program (list of images with routines)
	And testing any of them (also, addresses ranges 
	and saving instructions contexts)
*/

#include "FuzzingPinTool.h"
using namespace std;

struct InstructionInfo
{
	ADDRINT Address;
	string Disassembled;
	UINT32 VisitsCount;
	ADDRINT base;
};

struct ReadInfo
{
	ADDRINT ReadAddress;
	ADDRINT Offset;
	map<string, REG>::iterator RegisterPointer;
};

struct DataFromMemory
{
	ADDRINT Offset;
	ADDRINT ReadAddr;
	UINT32 IntVal;
	string StrVal;
	UINT32 RefIntVal;
	string RefStrVal;
};

typedef map<string, vector<ReadInfo>>				DataToRead;
typedef map<string, vector<DataFromMemory>>			ReadData;
typedef map<string, vector<string>>					RoutinesToTest;
typedef map<string, vector<pair<ADDRINT, ADDRINT>>> RangesToTest;

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
//vector<string> routinesToTest;
RoutinesToTest routinesToTest;

// Rtn ID -> {addr, disassemblies, visits counts}
map<UINT32, vector<InstructionInfo>> testedRtns;

// Rtn ID -> Rtn Name
map<UINT32, string> rtnsRefs;

// Rtn ID -> Rtn base address
map<UINT32, ADDRINT> rtnsBases;

// List of addresses ranges [From; To] for testing in a case
RangesToTest rangesToTest;

// Count of ranges in progress
UINT32 rangesCounter = 0;

// Traversed instructions
vector<InstructionInfo> insInRanges;

DataToRead toRead;

map<string, REG> regsRef;

ReadData readData;

/* R O U T I N E S */

VOID Outline_Image(IMG img, void*)
{
	vector<string> routines;
	string imgName = IMG_Name(img);
	ADDRINT base = IMG_LowAddress(img);
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
		{
			RTN_Open(rtn);
			routines.push_back(hexstr(INS_Address(RTN_InsHead(rtn)) - base) + "\t" + RTN_Name(rtn));
			RTN_Close(rtn);
		}
	}

	outline.insert(make_pair(hexstr(base) + " " + imgName, routines));
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

VOID ParseRead(string line, string &imgName, ADDRINT &insAddr, INT32 &readAddr, map<string, REG>::iterator &iter)
{
	UINT32 i = 0;
	i = line.find(' ');
	if (i == string::npos)
		return;

	imgName = line.substr(0, i);
	line = line.substr(i + 1);
	i = line.find(' ');
	
	if (i != string::npos)
	{
		string tmp = line.substr(0, i);
		insAddr = strtoul(tmp.c_str(), nullptr, 16);
		if (insAddr == 0)
			return;

		i++;
		tmp = line.substr(i, 3);
		iter = regsRef.find(tmp);

		if(iter != regsRef.end())
		{
			i += 3;
			if (line[i] == '-')
			{
				i++;
				tmp = line.substr(i, line.size());
				readAddr = 0 - strtol(tmp.c_str(), nullptr, 16);
				if (!readAddr)
				{
					insAddr = 0;
					readAddr = 0;
					iter = regsRef.end();
				}
			}
			else if (line[i] == '+')
			{
				i++;
				tmp = line.substr(i, line.size());
				readAddr = strtol(tmp.c_str(), nullptr, 16);
				if (!readAddr)
				{
					insAddr = 0;
					readAddr = 0;
					iter = regsRef.end();
				}
			}
			else if (i == line.length())
			{
				readAddr = 0;
			}
			else
			{
				insAddr = 0;
				readAddr = 0;
				iter = regsRef.end();
			}
		}
		else
		{
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
			{
				string imgName = "";
				string rtnName = "";
				ParseForRoutine(line, imgName, rtnName);
				if (imgName.size() && rtnName.size())
				{
					RoutinesToTest::iterator iter = routinesToTest.find(imgName);
					if (iter == routinesToTest.end())
					{
						vector<string> tmp;
						tmp.push_back(rtnName);
						routinesToTest.insert(make_pair(imgName, tmp));
					}
					else
					{
						iter->second.push_back(rtnName);
					}
				}
			}
		}
		else if (flags == 0x02)
		{
			if (line[0] != '#' && line.length())
			{
				string imgName;
				ADDRINT start = 0, end = 0;
				ParseForRange(line, imgName, start, end);
				if (start && end)
				{
					RangesToTest::iterator iter = rangesToTest.find(imgName);
					if (iter == rangesToTest.end())
					{
						vector<pair<ADDRINT, ADDRINT>> tmp;
						tmp.push_back(make_pair(start, end));
						rangesToTest.insert(make_pair(imgName, tmp));
					}
					else
					{
						iter->second.push_back(make_pair(start, end));
					}
				}
			}
		}
		else if (flags == 0x03)
		{
			// make it static
			if (regsRef.empty())
			{
				regsRef.insert(make_pair("eax", REG_EAX));
				regsRef.insert(make_pair("ebx", REG_EBX));
				regsRef.insert(make_pair("ecx", REG_ECX));
				regsRef.insert(make_pair("edx", REG_EDX));
				regsRef.insert(make_pair("esi", REG_ESI));
				regsRef.insert(make_pair("edi", REG_EDI));
				regsRef.insert(make_pair("esp", REG_ESP));
				regsRef.insert(make_pair("ebp", REG_EBP));
			}

			ADDRINT insAddr = 0; 
			INT32 readAddr = 0;
			string imgName = "";
			map<string, REG>::iterator iter;
			ParseRead(line, imgName, insAddr, readAddr, iter);
			if (insAddr)
			{
				ReadInfo ri;
				ri.ReadAddress = readAddr;
				ri.RegisterPointer = iter;
				ri.Offset = insAddr;
				DataToRead::iterator foundImg = toRead.find(imgName);
				if (foundImg == toRead.end())
				{
					vector<ReadInfo> vec;
					vec.push_back(ri);
					toRead.insert(make_pair(imgName, vec));
				}
				else
				{
					foundImg->second.push_back(ri);
				}
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
		OatFout << "[ROUTINE] " << endl << rtnsRefs[iter->first] << endl;
		OatFout << "Base Address:\t" << hexstr(rtnsBases[iter->first]) << endl;
		OatFout << "[DISASSEMBLED]\n";
		for (UINT32 i = 0; i < iter->second.size(); i++)
		{
			OatFout << hexstr(iter->second.at(i).Address) << "\t" << iter->second.at(i).Disassembled << " [" << iter->second.at(i).VisitsCount << "]\n";
		}
		OatFout << endl;
	}
	if (rangesToTest.size())
	{
		for (RangesToTest::iterator iter = rangesToTest.begin(); iter != rangesToTest.end(); iter++)
		{
			OatFout << "[IMAGE]" << endl << iter->first << endl << endl;
			OatFout << "[RANGES]" << endl;
			for (UINT32 i = 0; i < iter->second.size(); i++)
			{
				OatFout << hexstr(iter->second.at(i).first) << ":\t" << hexstr(iter->second.at(i).second) << endl;
			}
			OatFout << endl;
		}
		OatFout << "[INSTRUCTIONS]" << endl;
		for (UINT32 j = 0; j < insInRanges.size(); j++)
		{
			OatFout << hexstr(insInRanges.at(j).base) << ": " << hexstr(insInRanges.at(j).Address) << "\t" << insInRanges.at(j).Disassembled;
			OatFout << "\t[" << insInRanges.at(j).VisitsCount << "]\n";
		}
	}
	
	if (!readData.empty())
	{
		OatFout << "[READ FROM MEMORY]" << endl;
		for (ReadData::iterator rd = readData.begin(); rd != readData.end(); rd++)
		{
			OatFout << "Routine: " << rd->first << endl;
			for (UINT32 index = 0; index < rd->second.size(); index++)
			{
				OatFout << "\n\tOffset:\t" << hexstr(rd->second.at(index).Offset) << endl;
				OatFout << "\tAddress:\t" << hexstr(rd->second.at(index).ReadAddr) << endl;
				OatFout << "\tInteger:\t" << hexstr(rd->second.at(index).IntVal) << endl;
				OatFout << "\tString:\t" << rd->second.at(index).StrVal << endl;
				
				if (rd->second.at(index).RefIntVal)
					OatFout << "\tReferenced Integer:\t\t" << hexstr(rd->second.at(index).RefIntVal) << endl;
				else
					OatFout << "\tReferenced Integer:\t\tNULL\n";

				if (rd->second.at(index).RefIntVal & 0xff)
					OatFout << "\tReferenced String:\t\t" << rd->second.at(index).RefStrVal << endl;
				else
					OatFout << "\tReferenced String:\t\tNULL\n";

			}
			OatFout << endl;
		}
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

	IMG img = SEC_Img(RTN_Sec(rtn));
	string imgName = IMG_Name(img);
	RoutinesToTest::iterator iter = routinesToTest.find(imgName);
	if (iter == routinesToTest.end())
		return;

	string name = RTN_Name(rtn);
	if (find(iter->second.begin(), iter->second.end(), name) == iter->second.end())
		return;

	RTN_Open(rtn);

	UINT32 id = RTN_Id(rtn);
	if (testedRtns.find(id) == testedRtns.end())
	{
		rtnsRefs.insert(make_pair(id, name));
		ADDRINT base = IMG_LowAddress(img);
		rtnsBases.insert(make_pair(id, base));

		UINT32 counter = 0;
		vector<InstructionInfo> rtnInstructions;
		for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
		{
			InstructionInfo current;
			current.Address = INS_Address(ins) - base;
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

VOID ReadStringFromAddress(ADDRINT *from, string &val)
{
	val = "";
	char tmp = 0;
	UINT32 t = 0;
	while (true)
	{
		PIN_SafeCopy(&t, from, 4);
		if (t)
		{
			for (UINT32 i = 0; i < 4; i++)
			{
				char a = *(reinterpret_cast<char*>(&t) + i);
				if (a)
					val.push_back(a);
				else
					return;
			}
			t = 0;
			from++;
		}
		else
			return;
	}
}

VOID ReadFromAddress(vector<DataFromMemory> *vec, ADDRINT *from, ADDRINT offset)
{
	UINT32 intVal = 0;
	ADDRINT *readAddr = from;
	PIN_SafeCopy(&intVal, readAddr, 4);
	string strVal = "";
	ReadStringFromAddress(readAddr, strVal);

	UINT32 refIntVal = 0;
	string refStrVal = "";
	if (intVal)
	{
		ADDRINT *referencedVal = reinterpret_cast<ADDRINT*>(static_cast<ADDRINT>(intVal));
		PIN_SafeCopy(&refIntVal, referencedVal, 4);
		if (refIntVal & 0xff)
			ReadStringFromAddress(referencedVal, refStrVal);

	}

	DataFromMemory dfm;
	dfm.ReadAddr = reinterpret_cast<ADDRINT>(from);
	dfm.IntVal = intVal;
	dfm.StrVal = strVal;
	dfm.RefIntVal = refIntVal;
	dfm.RefStrVal = refStrVal;
	dfm.Offset = offset;

	vec->push_back(dfm);
}

VOID FromMemoryHandler(vector<DataFromMemory> *vec, ADDRINT readAddr, ADDRINT offset)
{
	ADDRINT *readAddrPtr = reinterpret_cast<ADDRINT*>(readAddr);
	ReadFromAddress(vec, readAddrPtr, offset);
}

VOID ReadWithRegHandler(vector<DataFromMemory> *vec, UINT32 offset, REG reg, ADDRINT addrOffset)
{
	ADDRINT *readAddr = reinterpret_cast<ADDRINT*> (reg + static_cast<INT32>(offset));
	ReadFromAddress(vec, readAddr, addrOffset);
}

VOID Test_Instruction(INS ins, void*)
{
	ADDRINT addr = INS_Address(ins);

	// Range part

	RTN rtn = INS_Rtn(ins);
	if (!RTN_Valid(rtn))
		return;

	IMG img = SEC_Img(RTN_Sec(rtn));
	string imgName = IMG_Name(img);
	ADDRINT base = IMG_LowAddress(img);
	addr -= base;
	RangesToTest::iterator im = rangesToTest.find(imgName);

	BOOL done = false;
	if (im != rangesToTest.end())
	{
		for (vector<pair<ADDRINT, ADDRINT>>::iterator iter = im->second.begin(); iter != im->second.end(); iter++)
		{
			if (iter->first == addr)
				rangesCounter++;

			if (rangesCounter && !done)
			{
				done = true;

				InstructionInfo insInfo;
				insInfo.Address = addr;
				insInfo.Disassembled = INS_Disassemble(ins);
				insInfo.VisitsCount = 0;
				insInfo.base = base;
				insInRanges.push_back(insInfo);

				INS_InsertCall(
					ins,
					IPOINT_BEFORE, (AFUNPTR)RangeInsHandler,
					IARG_UINT32, insInRanges.size() - 1,
					IARG_END
				);

			}

			if (rangesCounter && iter->second == addr)
				rangesCounter--;
		}
	}
	
	// Read part

	DataToRead::iterator iter = toRead.find(imgName);
	if (iter != toRead.end())
	{
		ReadData::iterator iter1 = readData.find(imgName);
		if (iter1 == readData.end())
			readData.insert(make_pair(imgName, vector<DataFromMemory>()));

		for (vector<ReadInfo>::iterator ri = iter->second.begin(); ri != iter->second.end(); ri++)
		{
			if (ri->Offset != addr)
				continue;

			if (ri->RegisterPointer != regsRef.end())
			{
				INS_InsertCall(
					ins,
					IPOINT_BEFORE, (AFUNPTR)ReadWithRegHandler,
					IARG_PTR, &readData[imgName],
					IARG_UINT32, static_cast<ADDRINT>(ri->ReadAddress),
					IARG_REG_VALUE, ri->RegisterPointer->second,
					IARG_ADDRINT, addr,
					IARG_END
				);
			}
			else
			{
				INS_InsertCall(
					ins,
					IPOINT_BEFORE, (AFUNPTR)FromMemoryHandler,
					IARG_ADDRINT, addr,
					IARG_ADDRINT, static_cast<ADDRINT>(ri->ReadAddress),
					IARG_ADDRINT, addr,
					IARG_END
				);
			}
		}

		
	}
}