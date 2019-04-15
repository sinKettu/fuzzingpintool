/* Tracking data in memory */

#include "FuzzingPinTool.h"
using namespace std;

ofstream TrackerFout;

vector<UINT8> charsToTrack;
vector<UINT16> shortsToTrack;
vector<UINT32> intsToTrack;
vector<string> stringsToTrack;

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
			bool ch = true;
			bool sh = false;
			bool in = false;
			bool st = false;
			getline(fin, line);
		}
		else if (!line.compare("[2]"))
		{
			bool ch = false;
			bool sh = true;
			bool in = false;
			bool st = false;
			getline(fin, line);
		}
		else if (!line.compare("[4]"))
		{
			bool ch = false;
			bool sh = false;
			bool in = true;
			bool st = false;
			getline(fin, line);
		}
		else if (!line.compare("[c]"))
		{
			bool ch = false;
			bool sh = false;
			bool in = false;
			bool st = true;
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