#pragma once
#include "FuzzingPinTool.h"
using namespace std;

typedef map<string, vector<string>> RoutinesToFuzz;
typedef map<string, vector<pair<ADDRINT, ADDRINT>>> RangesToFuzz;

/* GLOBALS */

RoutinesToFuzz routinesToFuzz;
RangesToFuzz rangesToFuzz;

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

VOID Fuzzer_Image(IMG img, void*)
{

}