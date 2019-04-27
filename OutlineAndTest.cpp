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
	ADDRINT InsAddress;
	ADDRINT ReadAddr;
	UINT32 IntVal;
	string StrVal;
};

// »з-за того, что map, нельз€ читать два адреса на одной инструкции
typedef map<ADDRINT, ReadInfo> ReadData;

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

map<string, REG> RegsRef;

vector<DataFromMemory> DataFromMemoryVec;

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

// —лучай когда не вычитаетс€ и не прибавл€етс€ ничего к регистру
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
		iter = RegsRef.find(tmp);

		if(iter != RegsRef.end())
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
					iter = RegsRef.end();
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
					iter = RegsRef.end();
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
				iter = RegsRef.end();
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
			if (RegsRef.empty())
			{
				RegsRef.insert(make_pair("eax", REG_EAX));
				RegsRef.insert(make_pair("ebx", REG_EBX));
				RegsRef.insert(make_pair("ecx", REG_ECX));
				RegsRef.insert(make_pair("edx", REG_EDX));
				RegsRef.insert(make_pair("esi", REG_ESI));
				RegsRef.insert(make_pair("edi", REG_EDI));
				RegsRef.insert(make_pair("esp", REG_ESP));
				RegsRef.insert(make_pair("ebp", REG_EBP));
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
				toRead.insert(make_pair(insAddr, ri));
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
	if (!DataFromMemoryVec.empty())
	{
		OatFout << "[READ FROM MEMORY]" << endl;
		for (UINT32 i = 0; i < DataFromMemoryVec.size(); i++)
		{
			OatFout << "At " << hexstr(DataFromMemoryVec.at(i).InsAddress) << ":" << endl;
			OatFout << "Integer Value:\t" << hexstr(DataFromMemoryVec.at(i).IntVal) << endl;
			OatFout << "String Value:\t" << DataFromMemoryVec.at(i).StrVal << endl;
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

VOID FromMemoryHandler(UINT32 index, ADDRINT readAddr)
{
	ADDRINT *readAddrPtr = reinterpret_cast<ADDRINT*>(readAddr);
	UINT32 intVal = 0;
	PIN_SafeCopy(&intVal, readAddrPtr, 4);
	string strVal = 0;
	char tmp = 0;
	while (true)
	{
		PIN_SafeCopy(&tmp, readAddrPtr, 1);
		if (tmp)
		{
			strVal.push_back(tmp);
			tmp = 0;
		}
		else
		{
			strVal.push_back(0);
			break;
		}
	}

	DataFromMemoryVec.at(index).IntVal = intVal;
	DataFromMemoryVec.at(index).StrVal = strVal;
	DataFromMemoryVec.at(index).ReadAddr = readAddr;
}

// —делать возможность читать не только из самого адреса
// Ќо и представить значение по данному адресу как адрес и прочитать по нему
VOID ReadWithRegHandler(UINT32 index, UINT32 offset, REG reg)
{
	ADDRINT *readAddr = reinterpret_cast<ADDRINT*> (reg + static_cast<INT32>(offset));
	UINT32 intVal = 0;
	PIN_SafeCopy(&intVal, readAddr, 4);
	string strVal = "";
	char tmp = 0;
	while (true)
	{
		PIN_SafeCopy(&tmp, readAddr, 1);
		if (tmp)
		{
			strVal.push_back(tmp);
			tmp = 0;
			readAddr++;
		}
		else
		{
			strVal.push_back(0);
			break;
		}
	}

	DataFromMemoryVec.at(index).IntVal = intVal;
	DataFromMemoryVec.at(index).StrVal = strVal;
	DataFromMemoryVec.at(index).ReadAddr = reinterpret_cast<ADDRINT>(readAddr);
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

	ReadData::iterator iter = toRead.find(addr);
	if (iter != toRead.end())
	{
		DataFromMemory dfm;
		dfm.InsAddress = addr;
		DataFromMemoryVec.push_back(dfm);

		if (iter->second.RegisterPointer != RegsRef.end())
		{
			INS_InsertCall(
				ins,
				IPOINT_BEFORE, (AFUNPTR)ReadWithRegHandler,
				IARG_UINT32, DataFromMemoryVec.size() - 1,
				IARG_UINT32, static_cast<UINT32>(iter->second.ReadAddress),
				IARG_REG_VALUE, (iter->second.RegisterPointer)->second,
				IARG_END
			);
		}
		else
		{
			INS_InsertCall(
				ins,
				IPOINT_BEFORE, (AFUNPTR)FromMemoryHandler,
				IARG_UINT32, DataFromMemoryVec.size() - 1,
				IARG_ADDRINT, static_cast<ADDRINT>(iter->second.ReadAddress),
				IARG_END
			);
		}
	}
}