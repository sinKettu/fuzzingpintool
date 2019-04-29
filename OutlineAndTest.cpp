/*  
	Outlines program (list of images with routines)
	And testing any of them (also, addresses ranges 
	and saving instructions contexts)
*/

#include "FuzzingPinTool.h"
using namespace std;

struct InstructionInfo
{
	UINT32 Address;
	string Disassembled;
	UINT32 VisitsCount;
};

struct ReadInfo
{
	INT32 ReadAddress;
	map<string, REG>::iterator RegisterPointer;
};

struct DataFromMemory
{
	ADDRINT ReadAddr;
	UINT32 IntVal;
	string StrVal;
	UINT32 RefIntVal;
	string RefStrVal;
};

// »з-за того, что map, нельз€ читать два адреса на одной инструкции
typedef map<ADDRINT, vector<ReadInfo>> DataToRead;
typedef map<ADDRINT, vector<DataFromMemory>> ReadData;

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

DataToRead toRead;

map<string, REG> regsRef;

//vector<DataFromMemory> DataFromMemoryVec;

ReadData readData;

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

VOID ParseRead(string line, ADDRINT &insAddr, INT32 &readAddr, map<string, REG>::iterator &iter)
{
	UINT32 i = 0;
	for (; i < line.length() && line[i] != ' '; i++){}
	if (i < line.length())
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
			map<string, REG>::iterator iter;
			ParseRead(line, insAddr, readAddr, iter);
			if (insAddr)
			{
				ReadInfo ri;
				ri.ReadAddress = readAddr;
				ri.RegisterPointer = iter;
				DataToRead::iterator foundAddr = toRead.find(insAddr);
				if (foundAddr == toRead.end())
				{
					vector<ReadInfo> vec;
					vec.push_back(ri);
					toRead.insert(make_pair(insAddr, vec));
				}
				else
				{
					foundAddr->second.push_back(ri);
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
	if (!readData.empty())
	{
		OatFout << "[READ FROM MEMORY]" << endl;
		for (ReadData::iterator rd = readData.begin(); rd != readData.end(); rd++)
		{
			OatFout << "Instruction Address: " << hexstr(rd->first) << endl;
			for (UINT32 index = 0; index < rd->second.size(); index++)
			{
				OatFout << "\n\tAddress:\t" << hexstr(rd->second.at(index).ReadAddr) << endl;
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

VOID ReadFromAddress(ADDRINT at, ADDRINT *from)
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

	readData[at].push_back(dfm);
}

VOID FromMemoryHandler(ADDRINT addr, ADDRINT readAddr)
{
	ADDRINT *readAddrPtr = reinterpret_cast<ADDRINT*>(readAddr);
	ReadFromAddress(addr, readAddrPtr);
}

// —делать возможность читать не только из самого адреса
// Ќо и представить значение по данному адресу как адрес и прочитать по нему
VOID ReadWithRegHandler(ADDRINT addr, UINT32 offset, REG reg)
{
	ADDRINT *readAddr = reinterpret_cast<ADDRINT*> (reg + static_cast<INT32>(offset));
	ReadFromAddress(addr, readAddr);
}

// ѕри чтении из пам€ти запоминаетс€ значение
// ќт последнего посещени€ инструкции, а не все!
VOID Test_Instruction(INS ins, void*)
{
	ADDRINT addr = INS_Address(ins);

	// Range part

	for (map<ADDRINT, ADDRINT>::iterator iter = rangesToTest.begin(); iter != rangesToTest.end(); iter++)
	{
		if (iter->first == addr)
			rangesCounter++;

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

		if (rangesCounter && iter->second == addr)
			rangesCounter--;
	}

	// Read part

	DataToRead::iterator iter = toRead.find(addr);
	if (iter != toRead.end())
	{
		ReadData::iterator iter1 = readData.find(addr);
		if (iter1 == readData.end())
			readData.insert(make_pair(addr, vector<DataFromMemory>()));

		for (vector<ReadInfo>::iterator ri = iter->second.begin(); ri != iter->second.end(); ri++)
		{
			if (ri->RegisterPointer != regsRef.end())
			{
				INS_InsertCall(
					ins,
					IPOINT_BEFORE, (AFUNPTR)ReadWithRegHandler,
					IARG_ADDRINT, addr,
					IARG_UINT32, static_cast<UINT32>(ri->ReadAddress),
					IARG_REG_VALUE, ri->RegisterPointer->second,
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
					IARG_END
				);
			}
		}

		
	}
}