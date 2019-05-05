#include "FuzzingPinTool.h"
using namespace std;

typedef map<string, vector<string>>					RoutinesToFuzz;
typedef map<string, vector<pair<ADDRINT, ADDRINT>>> RangesToFuzz;
typedef map<UINT32, vector<pair<ADDRINT, UINT32>>>	SavedRoutineData;

/* GLOBALS */

RoutinesToFuzz routinesToFuzz;
RangesToFuzz rangesToFuzz;
SavedRoutineData savedRtnData;
map<UINT32, CONTEXT> savedRtnCtxt;
BOOL fuzzingInProgress = false;

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

VOID CheckIfFirst(UINT32 id, CONTEXT ctxt)
{
	if (fuzzingInProgress || savedRtnCtxt.find(id) != savedRtnCtxt.end())
		return;

	savedRtnCtxt.insert(make_pair(id, ctxt));
}

VOID HandleRtnMemoryRead(UINT32 id, ADDRINT ea, UINT32 size)
{
	if (fuzzingInProgress)
	{
		// pass
	}
	else
	{
		if (size > sizeof(ADDRINT))
			return;

		UINT32 val = 0;
		ADDRINT *ptr = reinterpret_cast<ADDRINT *>(ea);
		PIN_SafeCopy(&val, ptr, size);

		savedRtnData[id].push_back(make_pair(ea, val));
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
						IARG_CONTEXT,
						IARG_END
					);

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
				}
			}
		}
	}
}