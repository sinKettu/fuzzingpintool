/* BBL Trace of images */
#include "FuzzingPinTool.h"
using namespace std;

typedef vector<map<ADDRINT, UINT32>> BblCounter;

/* Globals */

ofstream TrcFout;

// Images to get trace
vector<string> trcImages;

// Visited images
vector<string> images;

// Base addresses of images
map<string, ADDRINT> imageBases;

// Bbl visits counter (related to images)
BblCounter bblCounter;

BOOL Tracer_LoadList(string path)
{
	ifstream fin;
	fin.open(path.c_str());
	if (!fin.is_open())
		return false;

	string line;
	while (!fin.eof())
	{
		getline(fin, line);
		if (line.length() && line[0] != '#')
		{
			trcImages.push_back(line);
		}
	}

	fin.close();
	return true;
}

VOID RtnBblCounter(UINT32 imgIndex, ADDRINT addr)
{
	if (imgIndex < bblCounter.size())
		bblCounter.at(imgIndex)[addr]++;
}

VOID Tracer_Trace(TRACE trc, void*)
{
	RTN rtn = TRACE_Rtn(trc);
	if (!RTN_Valid(rtn))
		return;

	IMG img = SEC_Img(RTN_Sec(rtn));
	string name = IMG_Name(img);
	if (find(trcImages.begin(), trcImages.end(), name) == trcImages.end())
		return;

	vector<string>::iterator iter = find(images.begin(), images.end(), name);
	UINT32 index = 0;
	ADDRINT base = 0;
	if (iter == images.end())
	{
		images.push_back(name);
		map<ADDRINT, UINT32> tmp;
		bblCounter.push_back(tmp);
		index = bblCounter.size() - 1;
		base = IMG_LowAddress(img);
		imageBases.insert(make_pair(name, base));
	}
	else
	{
		index = iter - images.begin();
		base = imageBases[*iter];
	}

	for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		ADDRINT addr = INS_Address(BBL_InsHead(bbl)) - base;
		bblCounter.at(index).insert(make_pair(addr, 0));

		BBL_InsertCall(
			bbl,
			IPOINT_BEFORE, (AFUNPTR)RtnBblCounter,
			IARG_UINT32, index,
			IARG_ADDRINT, addr,
			IARG_END
		);
	}
}

VOID Tracer_Fini(INT32 code, void*)
{
	if (!images.empty())
	{
		TrcFout.open("outdata.txt", ios::app);
		TrcFout << "[TRACE]" << endl;
		for (UINT32 i = 0; i < images.size(); i++)
		{
			TrcFout << "[IMAGE]\t" << images.at(i) << "\t" << hexstr(imageBases[images.at(i)]) << endl;
			for (map<ADDRINT, UINT32>::iterator iter = bblCounter.at(i).begin(); iter != bblCounter.at(i).end(); iter++)
			{
				TrcFout << "\t" << hexstr(iter->first) << ": " << iter->second << endl;
			}
		}
		TrcFout << endl;
		TrcFout.close();
	}
}