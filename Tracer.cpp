/* BBL Trace of images */
#include "FuzzingPinTool.h"
using namespace std;

ofstream TrcFout;
vector<string> imagesList;
vector<string> images;
vector<vector<ADDRINT>> bbls;
vector<vector<UINT32>> visits;

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
			imagesList.push_back(line);
		}
	}

	fin.close();
	return true;
}

VOID BblCounter(UINT32 imgIndex, UINT32 bblIndex)
{
	if (imgIndex < visits.size() && bblIndex < visits[imgIndex].size())
		visits[imgIndex][bblIndex]++;
}

VOID Tracer_Trace(TRACE trc, void*)
{
	RTN rtn = TRACE_Rtn(trc);
	if (!RTN_Valid(rtn))
		return;

	IMG img = SEC_Img(RTN_Sec(rtn));
	string name = IMG_Name(img);
	if (find(imagesList.begin(), imagesList.end(), name) == imagesList.end())
		return;

	vector<string>::iterator iter = find(images.begin(), images.end(), name);
	UINT32 index = 0;
	if (iter == images.end())
	{
		images.push_back(name);
		
		vector<ADDRINT> vec1;
		vec1.clear();
		bbls.push_back(vec1);

		vector<UINT32> vec2;
		vec2.clear();
		visits.push_back(vec2);
	}
	else
	{
		index = iter - images.begin();
	}

	UINT32 count = bbls.at(index).empty() ? 0 : bbls.at(index).size();
	for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		ADDRINT addr = INS_Address(BBL_InsHead(bbl));
		bbls.at(index).push_back(addr);
		visits.at(index).push_back(0);

		BBL_InsertCall(
			bbl,
			IPOINT_BEFORE, (AFUNPTR)BblCounter,
			IARG_UINT32, index,
			IARG_UINT32, count,
			IARG_END
		);

		count++;
	}
}

VOID Tracer_Fini(INT32 code, void*)
{
	if (!images.empty())
	{
		TrcFout.open("outdata.txt", ios::app);
		for (UINT32 i = 0; i < images.size(); i++)
		{
			TrcFout << images.at(i) << endl;
			if (!bbls.empty())
			{
				for (UINT32 j = 0; j < bbls.at(i).size(); j++)
				{
					TrcFout << "\t" << hexstr(bbls.at(i).at(j)) << ": " << visits.at(i).at(j) << endl;
				}
			}
		}
		TrcFout.close();
	}
}