#include "FuzzingPinTool.h"
using namespace std;

#define PREPARATORY_PHASE	0
#define FUZZING_PHASE		1

struct MemoryData
{
	ADDRINT Address;
	ADDRINT Value;
	ADDRINT Size;
};

typedef map<string, vector<string>>					RoutinesToFuzz;
typedef map<string, vector<pair<ADDRINT, ADDRINT>>> RangesToFuzz;
typedef map<UINT32, vector<MemoryData>>	SavedRoutineData;

/* GLOBALS */

RoutinesToFuzz routinesToFuzz;
RangesToFuzz rangesToFuzz;
SavedRoutineData savedRtnData;
map<UINT32, CONTEXT> savedRtnCtxt;
map<UINT32, ADDRINT> rtnEntryAddress;
UINT32 fuzzedCodeId = 0;
CONTEXT replacingCtxt;
UINT8 phase = PREPARATORY_PHASE;
REG regArray[7] = { REG_EAX, REG_EBX, REG_ECX, REG_EDX, REG_ESI, REG_EDI, REG_EBP };
map<ADDRINT, UINT32> lastTrace;
map<ADDRINT, UINT32> currentTrace;

/* ROUTINES */

VOID ParseForRoutine(string str, string &imgName, string &rtnName)
{
	UINT32 index = str.find(' ');
	if (index == string::npos)
	{
		imgName = "";
		rtnName = "";
	}
	else
	{
		imgName = str.substr(0, index);
		rtnName = str.substr(index + 1, str.length() - index - 1);
	}
}

VOID ParseForRange(string str, string &imgName, ADDRINT &s, ADDRINT &e)
{
	UINT32 index = str.find(' ');
	if (index != string::npos)
	{
		imgName = str.substr(0 + index);
		index++;
		char *c;
		s = static_cast<ADDRINT>(strtoul(str.c_str() + index, &c, 16));
		if (errno == ERANGE)
		{
			s = 0;
			return;
		}
		e = static_cast<ADDRINT>(strtoul(c, nullptr, 16));
		if (errno == ERANGE)
		{
			e = 0;
			return;
		}
	}
}

BOOL Fuzzer_LoadList(string path)
{
	ifstream fin;
	fin.open(path.c_str());
	if (!fin.is_open())
		return false;

	string line;
	UINT8 flag = 0;

	while (true)
	{
		getline(fin, line);

		if (!line.compare("[ROUTINE]"))
		{
			flag = 1;
			continue;
		}
		else if (!line.compare("[RANGE]"))
		{
			flag = 2;
			continue;
		}

		if (flag == 1)
		{
			string rtnName = "";
			string imgName = "";
			ParseForRoutine(line, imgName, rtnName);
			if (imgName.size() && rtnName.size())
			{
				RoutinesToFuzz::iterator iter = routinesToFuzz.find(imgName);
				if (iter == routinesToFuzz.end())
				{
					vector<string> tmp;
					tmp.push_back(rtnName);
					routinesToFuzz.insert(make_pair(imgName, tmp));
				}
				else
				{
					iter->second.push_back(rtnName);
				}
			}
		}
		else if (flag == 2)
		{
			string imgName = "";
			ADDRINT start = 0;
			ADDRINT end = 0;
			ParseForRange(line, imgName, start, end);
			if (imgName.size() && start && end)
			{
				RangesToFuzz::iterator iter = rangesToFuzz.find(imgName);
				if (iter == rangesToFuzz.end())
				{
					vector<pair<ADDRINT, ADDRINT>> tmp;
					tmp.push_back(make_pair(start, end));
					routinesToFuzz.insert(make_pair(imgName, tmp));
				}
				else
				{
					iter->second.push_back(make_pair(start, end));
				}
			}
		}

		if (fin.eof())
			break;
	}

	fin.close();
	return true;
}

VOID CheckIfFirst(UINT32 id, ADDRINT addr, CONTEXT ctxt)
{
	if (phase == PREPARATORY_PHASE)
	{
		if (fuzzedCodeId != 0 || savedRtnCtxt.find(id) != savedRtnCtxt.end())
			return;

		savedRtnCtxt.insert(make_pair(id, ctxt));
		rtnEntryAddress.insert(make_pair(id, addr));
		fuzzedCodeId = id;
	}
}

VOID MutateReg(UINT32 choice)
{
	ADDRINT val = rand() & UINT32_MAX;
	PIN_SetContextReg(&replacingCtxt, regArray[choice], val);
}

VOID MutateMemoryVal(UINT32 id, UINT32 choice)
{
	if (savedRtnData[id].empty())
		return;

	choice -= 8;
	ADDRINT *ea = reinterpret_cast<ADDRINT*>(savedRtnData[id].at(choice).Address);
	UINT32 mask = (1 << (8 * savedRtnData[id].at(choice).Size)) - 1;
	UINT32 val = rand() & mask;
	
	PIN_SafeCopy(ea, &val, savedRtnData[id].at(choice).Size);
}

VOID Mutate(UINT32 id)
{
	UINT32 choice = rand() % (savedRtnData[id].size() + 7);
	if (choice < 7)
	{
		MutateReg(choice);
	}
	else
	{
		choice -= 7;
		MutateMemoryVal(id, choice);
	}
}

VOID HandleRtnMemoryRead(UINT32 id, ADDRINT ea, UINT32 size)
{
	if (phase == PREPARATORY_PHASE && id == fuzzedCodeId)
	{
		if (size > sizeof(ADDRINT))
			return;

		ADDRINT val = 0;
		ADDRINT *ptr = reinterpret_cast<ADDRINT *>(ea);
		PIN_SafeCopy(&val, ptr, size);

		MemoryData tmp;
		tmp.Address = ea;
		tmp.Value = val;
		tmp.Size = size;

		savedRtnData[id].push_back(tmp);
	}
	else if (phase == FUZZING_PHASE && id == fuzzedCodeId)
	{
		// put memory mutations here
		Mutate(id);

		// make conditions to end fuzzing
	}
}

VOID HandleRtnRet(UINT32 id)
{
	if (phase == PREPARATORY_PHASE && id == fuzzedCodeId)
	{
		map<UINT32, CONTEXT>::iterator rtnCtxt = savedRtnCtxt.find(id);
		if (rtnCtxt != savedRtnCtxt.end())
		{
			fuzzedCodeId = id;
			PIN_SaveContext(&rtnCtxt->second, &replacingCtxt);

			// put context mutations here
			srand(time(nullptr));
			UINT32 choice = rand() % (savedRtnData[id].size() + 7);
			Mutate(id);

			phase = FUZZING_PHASE;
			PIN_ExecuteAt(&replacingCtxt);
		}
	}
	else if (phase == FUZZING_PHASE && id == fuzzedCodeId)
	{
		// put context mutations here
		Mutate(id);

		PIN_ExecuteAt(&replacingCtxt);
	}
}

VOID FuzzerBblCounter(ADDRINT headIns, UINT32 id)
{
	if (phase == PREPARATORY_PHASE && id == fuzzedCodeId)
	{
		lastTrace[headIns]++;
	}
	else if (phase == FUZZING_PHASE && id == fuzzedCodeId)
	{
		currentTrace[headIns]++;
	}
}

VOID Fuzzer_Image(IMG img, void*)
{
	if (!IMG_Valid(img))
		return;

	string imgName = IMG_Name(img);
	RoutinesToFuzz::iterator ii = routinesToFuzz.find(imgName);
	if (ii == routinesToFuzz.end())
		return;

	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
		{
			string rtnName = RTN_Name(rtn);
			vector<string>::iterator ri = find(ii->second.begin(), ii->second.end(), rtnName);
			if (ri != ii->second.end())
			{
				UINT32 id = RTN_Id(rtn);
				savedRtnData.insert(make_pair(id, vector<pair<ADDRINT, UINT32>>()));

				for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
				{
					// Save rtn context if ins is first entry
					// head ins isn't first entry all the time (O_o)
					INS_InsertCall(
						ins,
						IPOINT_BEFORE, (AFUNPTR)CheckIfFirst,
						IARG_UINT32, id,
						IARG_ADDRINT, INS_Address(ins),
						IARG_CONTEXT,
						IARG_END
					);

					// If ins is reading from memory:
					// - save (address, value) in first phase to recover later
					// - replace valid data on random in second phase
					if (INS_IsMemoryRead(ins))
					{
						INS_InsertCall(
							ins,
							IPOINT_BEFORE, (AFUNPTR)HandleRtnMemoryRead,
							IARG_UINT32, id,
							IARG_MEMORYREAD_EA,
							IARG_MEMORYREAD_SIZE,
							IARG_END
						);
					}

					// If ins is ret, fuzzing will be started or continued
					// from first rtn entry
					if (INS_IsRet(ins))
					{
						INS_InsertCall(
							ins,
							IPOINT_BEFORE, (AFUNPTR)HandleRtnRet,
							IARG_UINT32, id,
							IARG_END
						);
					}
				}

				for (BBL bbl = RTN_BblHead(rtn); BBL_Valid(bbl); bbl = BBL_Next(bbl))
				{
					ADDRINT bblHead = INS_Address(BBL_InsHead(bbl));
					lastTrace.insert(make_pair(bblHead, 0));
					currentTrace.insert(make_pair(bblHead, 0));

					BBL_InsertCall(
						bbl,
						IPOINT_BEFORE, (AFUNPTR)FuzzerBblCounter,
						IARG_ADDRINT, bblHead,
						IARG_UINT32, id,
						IARG_END
					);
				}
			}
		}
	}
}

VOID Fuzzer_Trace(TRACE trc, void*)
{
	// pass
}