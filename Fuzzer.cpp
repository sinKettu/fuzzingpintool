#include "FuzzingPinTool.h"
using namespace std;

#define PREPARATORY_PHASE			0
#define FUZZING_PHASE				1
#define ATTEMPTS_PER_VAL_COUNT		3
#define HEAP_VALUE_SIZE_MASK		2047
#define FAILURE						30

struct MemoryData
{
	ADDRINT Address;
	ADDRINT Value;
	ADDRINT Size;
};

typedef map<string, vector<string>>					RoutinesToFuzz;
typedef map<string, vector<pair<ADDRINT, ADDRINT>>> RangesToFuzz;
typedef map<UINT32, vector<MemoryData>>				SavedRoutineData;

/* GLOBALS */

ofstream FuzFout;

REG regArray[7] = { REG_EAX, REG_EBX, REG_ECX, REG_EDX, REG_ESI, REG_EDI, REG_EBP };

// Given routines to fuzz
RoutinesToFuzz routinesToFuzz;

// Given ranges to fuzz
RangesToFuzz rangesToFuzz;

// Saved (address, value, size) at readings in preparatory phase
SavedRoutineData savedRtnData;

// Saved rtn entry context
map<UINT32, CONTEXT> savedRtnCtxt;

// Saved rtn entry address
map<UINT32, ADDRINT> rtnEntryAddress;

// ID of code part which is currently fuzzed
UINT32 fuzzedCodeId = 0;

// Entry context to mutate/restart
CONTEXT replacingCtxt;

// Current phase
UINT8 phase = PREPARATORY_PHASE;

// Traversed BBLs in last time and now
map<ADDRINT, UINT32> lastTrace;
map<ADDRINT, UINT32> currentTrace;

// Stack of successful mutated values
vector<UINT32> mutationStack;

// Stack of unsuccessful mutated values (to not be repeated)
vector<UINT32> unsuccessfulAttempts;

// Count of mutations per value
// before you consider it a failure
UINT8 mutationsCounter = ATTEMPTS_PER_VAL_COUNT;

// flag
BOOL memoryMutated = false;

// Random data stored in heap to replace
UINT8 *heapVal;
UINT32 heapValSize;

// Number of values which can be mutated
UINT32 mutationCandidatesCounter = 0;

UINT32 failureCounter = 0;

/* ROUTINES */

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
		if (line[0] == '#' || line.empty())
			continue;

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
					rangesToFuzz.insert(make_pair(imgName, tmp));
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

VOID CheckIfFirst(UINT32 id, ADDRINT addr, CONTEXT *ctxt)
{
	if (phase == PREPARATORY_PHASE)
	{
		if (fuzzedCodeId != 0 || savedRtnCtxt.find(id) != savedRtnCtxt.end())
			return;
		
		CONTEXT tmp;
		PIN_SaveContext(ctxt, &tmp);
		savedRtnCtxt.insert(make_pair(id, tmp));
		rtnEntryAddress.insert(make_pair(id, addr));
		fuzzedCodeId = id;
	}
}

VOID RandomiseHeap()
{
	delete[] heapVal;
	heapValSize = rand() & HEAP_VALUE_SIZE_MASK;
	heapVal = new UINT8[heapValSize];
	memset(heapVal, rand() & 0xff, heapValSize);
}

VOID MutateReg(UINT32 choice)
{
	UINT8 useHeap = rand() & 1;
	ADDRINT val;
	if (useHeap)
	{
		RandomiseHeap();
		val = reinterpret_cast<ADDRINT>(heapVal);
	}
	else
		val = rand() & UINT32_MAX;

	PIN_SetContextReg(&replacingCtxt, regArray[choice], val);
}

VOID MutateMemoryVal(UINT32 id, UINT32 choice)
{
	if (savedRtnData[id].empty())
		return;

	UINT8 useHeap = rand() & 1;
	ADDRINT *ea = reinterpret_cast<ADDRINT*>(savedRtnData[id].at(choice).Address);
	ADDRINT val;
	if (savedRtnData[id].at(choice).Size == 4 && useHeap)
	{
		RandomiseHeap();
		val = reinterpret_cast<ADDRINT>(heapVal);
	}
	else
	{
		UINT32 mask = (1 << (8 * savedRtnData[id].at(choice).Size)) - 1;
		val = rand() & mask;
	}
	
	PIN_SafeCopy(ea, &val, savedRtnData[id].at(choice).Size);
}

BOOL CompareTraces()
{
	UINT32 lastSum = 0;
	UINT32 currentSum = 0;

	for (map<ADDRINT, UINT32>::iterator iter = lastTrace.begin(); iter != lastTrace.end(); iter++)
	{
		lastSum += iter->second;
		currentSum += currentTrace[iter->first];

		iter->second = currentTrace[iter->first];
		currentTrace[iter->first] = 0;
	}
	
	return currentSum > lastSum;
}

VOID HandleRtnMemoryRead(UINT32 id, ADDRINT ea, UINT32 size)
{
	if (phase == PREPARATORY_PHASE && id == fuzzedCodeId)
	{
		if (size > sizeof(ADDRINT))
			return;

		for (vector<MemoryData>::iterator iter = savedRtnData[id].begin(); iter != savedRtnData[id].end(); iter++)
			if (iter->Address == ea)
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
		UINT32 choice = mutationStack.back();
		if (choice >= 7 && savedRtnData[id].at(choice - 7).Address == ea && !memoryMutated)
		{
			memoryMutated = true;
			MutateMemoryVal(id, choice - 7);
		}
	}
}

VOID RestoreMemory(UINT32 id)
{
	if (savedRtnData[id].empty())
		return;

	for (UINT32 index = 0; index < savedRtnData[id].size(); index++)
	{
		ADDRINT *addr = reinterpret_cast<ADDRINT*>(savedRtnData[id].at(index).Address);
		PIN_SafeCopy(addr, &savedRtnData[id].at(index).Value, savedRtnData[id].at(index).Size);
	}
}

BOOL GetNext(UINT32 id)
{
	if (failureCounter == FAILURE)
	{
		PIN_SaveContext(&savedRtnCtxt[id], &replacingCtxt);
		RestoreMemory(id);

		UINT32 tmp = *mutationStack.begin();
		tmp++;
		mutationStack.clear();
		if (tmp >= mutationCandidatesCounter)
		{
			return false;
		}
		else
		{
			mutationStack.push_back(tmp);
			failureCounter = 0;
			return true;
		}
	}

	if (mutationStack.back() < 7)
	{
		ADDRINT reg = PIN_GetContextReg(&savedRtnCtxt[id], regArray[mutationStack.back()]);
		PIN_SetContextReg(&replacingCtxt, regArray[mutationStack.back()], reg);
	}
	else
	{
		UINT32 choice = mutationStack.back() - 7;
		ADDRINT *addr = reinterpret_cast<ADDRINT*>(savedRtnData[id].at(choice).Address);
		PIN_SafeCopy(addr, &savedRtnData[id].at(choice).Value, savedRtnData[id].at(choice).Size);
	}

	UINT32 msb = ++mutationStack.back();
	bool exhausted = false;
	mutationStack.pop_back();
	while (true)
	{
		if (msb >= mutationCandidatesCounter)
		{
			if (!mutationStack.empty())
			{
				msb = ++mutationStack.back();
				mutationStack.pop_back();
				continue;
			}
			else
			{
				return false;
			}
		}

		if (find(mutationStack.begin(), mutationStack.end(), msb) != mutationStack.end())
			msb++;
		else
			break;
	}

	mutationStack.push_back(msb);
	return true;
}

BOOL NextMutation1(UINT32 id, BOOL exception = false)
{
	if (!id && exception)
	{
		// in case if exception is occurred
	}
	else if (mutationStack.empty())
	{
		mutationStack.push_back(0);
		mutationsCounter = ATTEMPTS_PER_VAL_COUNT;
	}
	else if (CompareTraces())
	{
		failureCounter = 0;
		if (mutationStack.size() == mutationCandidatesCounter)
			mutationStack.back()++;
		else
			mutationStack.push_back(0);

		mutationsCounter = ATTEMPTS_PER_VAL_COUNT;
		return GetNext(id);
	}
	else if (mutationsCounter == 0)
	{
		failureCounter++;
		mutationsCounter = ATTEMPTS_PER_VAL_COUNT;
		return GetNext(id);
	}
	else
	{
		failureCounter++;
		mutationsCounter--;
	}

	return true;
}

VOID HandleRtnRet(UINT32 id)
{
	if (phase == PREPARATORY_PHASE && id == fuzzedCodeId)
	{
		map<UINT32, CONTEXT>::iterator rtnCtxt = savedRtnCtxt.find(id);
		if (rtnCtxt != savedRtnCtxt.end())
		{
			fuzzedCodeId = id;
			phase = FUZZING_PHASE;
			mutationCandidatesCounter = 7 + savedRtnData[id].size();
			PIN_SaveContext(&rtnCtxt->second, &replacingCtxt);

			// put context mutations here
			srand(time(nullptr));
			heapVal = new UINT8[1];
			NextMutation1(id);
			if (mutationStack.back() < 7)
				MutateReg(mutationStack.back());

			PIN_ExecuteAt(&replacingCtxt);
		}
	}
	else if (phase == FUZZING_PHASE && id == fuzzedCodeId)
	{
		// put context mutations here
		memoryMutated = false;
		if (NextMutation1(id))
		{
			if (mutationStack.back() < 7)
				MutateReg(mutationStack.back());

			PIN_ExecuteAt(&replacingCtxt);
		}
		else
		{
			phase = PREPARATORY_PHASE;
			RestoreMemory(id);
			//PIN_ExecuteAt(&savedRtnCtxt[id]);
		}
	}
	
}

VOID FuzzerBblCounter(UINT32 id, UINT32 *last, UINT32 *current)
{
	if (phase == PREPARATORY_PHASE && id == fuzzedCodeId)
	{
		(*last)++;
	}
	else if (phase == FUZZING_PHASE && id == fuzzedCodeId)
	{
		(*current)++;
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
				RTN_Open(rtn);
				UINT32 id = RTN_Id(rtn);
				savedRtnData.insert(make_pair(id, vector<MemoryData>()));

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

				RTN_Close(rtn);
			}
		}
	}
}

VOID Fuzzer_Trace(TRACE trc, void*)
{
	RTN rtn = TRACE_Rtn(trc);
	if (!RTN_Valid(rtn))
		return;

	RTN_Open(rtn);
	IMG img = SEC_Img(RTN_Sec(rtn));
	string rtnName = RTN_Name(rtn);
	string imgName = IMG_Name(img);
	UINT32 id = RTN_Id(rtn);
	RTN_Close(rtn);

	RoutinesToFuzz::iterator ii = routinesToFuzz.find(imgName);
	if (ii == routinesToFuzz.end())
		return;

	vector<string>::iterator ri = find(ii->second.begin(), ii->second.end(), rtnName);
	if (ri == ii->second.end())
		return;

	for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		ADDRINT bblHead = INS_Address(BBL_InsHead(bbl));
		lastTrace.insert(make_pair(bblHead, 0));
		currentTrace.insert(make_pair(bblHead, 0));

		BBL_InsertCall(
			bbl,
			IPOINT_BEFORE, (AFUNPTR)FuzzerBblCounter,
			IARG_UINT32, id,
			IARG_PTR, &lastTrace[bblHead],
			IARG_PTR, &currentTrace[bblHead],
			IARG_END
		);
	}

}

VOID Fuzzer_ExceptionHandler(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, 
							const CONTEXT *from, CONTEXT *to, INT32 info, void *)
{
	if (reason == CONTEXT_CHANGE_REASON_EXCEPTION)
	{
		cout << endl << "Windwos exception is catched" << endl;
		cout << "Exception code: " << info << endl << endl;
		cout << "Occured at " << mutationStack.back() + 1 << " mutated:" << endl;

		if (phase == FUZZING_PHASE && fuzzedCodeId != 0)
		{
			cout << "1.\tEAX " << hexstr(PIN_GetContextReg(from, REG_EAX)) << endl;
			cout << "2.\tEBX " << hexstr(PIN_GetContextReg(from, REG_EBX)) << endl;
			cout << "3.\tECX " << hexstr(PIN_GetContextReg(from, REG_ECX)) << endl;
			cout << "4.\tEDX " << hexstr(PIN_GetContextReg(from, REG_EDX)) << endl;
			cout << "5.\tESI " << hexstr(PIN_GetContextReg(from, REG_ESI)) << endl;
			cout << "6.\tEDI " << hexstr(PIN_GetContextReg(from, REG_EDI)) << endl;
			cout << "7.\tEBP " << hexstr(PIN_GetContextReg(from, REG_EBP)) << endl;
			cout << "(\tESP " << hexstr(PIN_GetContextReg(from, REG_ESP)) << "  )" << endl;
			cout << "(\tEIP " << hexstr(PIN_GetContextReg(from, REG_EIP)) << "  )" << endl;
			for (UINT32 index = 0; index < savedRtnData[fuzzedCodeId].size(); index++)
			{
				cout << index + 8 << ".\tAddress: " << hexstr(savedRtnData[fuzzedCodeId].at(index).Address) << "; ";
				UINT32 val = 0;
				ADDRINT *ea = reinterpret_cast<ADDRINT*>(savedRtnData[fuzzedCodeId].at(index).Address);
				PIN_SafeCopy(&val, ea, savedRtnData[fuzzedCodeId].at(index).Size);
				cout << "Value: " << hexstr(val) << endl;
			}


			PIN_ExecuteAt(&replacingCtxt);
		}
		else
		{
			cout << "---" << endl;
		}
	}
}