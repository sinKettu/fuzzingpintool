#include <stdio.h>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include "FuzzingPinTool.h"
using namespace std;

#define		BASIC_BLOCK_EDGES	pair<UINT32, UINT32>
#define		BASIC_BLOCKS		map<BASIC_BLOCK_EDGES, UINT32>
#define		ROUTINES			map<string, BASIC_BLOCKS>
#define		SECTIONS			map<string, ROUTINES>
#define		IMAGES				map<string, SECTIONS>

IMAGES images;
UINT64 bblCount = 0;

VOID BblInstrumentation(
	const string *rtnName, 
	const string *secName,
	const string *imgName,
	UINT32 head, 
	UINT32 tail)
{
	bblCount++;
	BASIC_BLOCK_EDGES newEdges = make_pair(head, tail);
	IMAGES::iterator image = images.find(*imgName);
	if (image != images.end())
	{
		SECTIONS::iterator section = image->second.find(*secName);
		if (section != image->second.end())
		{
			ROUTINES::iterator routine = section->second.find(*rtnName);
			if (routine != section->second.end())
			{
				BASIC_BLOCKS::iterator bbl = routine->second.find(newEdges);
				if (bbl != routine->second.end())
					bbl->second++;
				else
					routine->second.insert(make_pair(newEdges, 1));
			}
			else
			{
				BASIC_BLOCKS bbl_tmp;
				bbl_tmp.insert(make_pair(newEdges, 1));
				section->second.insert(make_pair(*rtnName, bbl_tmp));
			}
		}
		else
		{
			BASIC_BLOCKS bbl_tmp;
			bbl_tmp.insert(make_pair(newEdges, 1));
			ROUTINES rtn_tmp;
			rtn_tmp.insert(make_pair(*rtnName, bbl_tmp));
			image->second.insert(make_pair(*secName, rtn_tmp));
		}
	}
	else
	{
		BASIC_BLOCKS bbl_tmp;
		bbl_tmp.insert(make_pair(newEdges, 1));
		ROUTINES rtn_tmp;
		rtn_tmp.insert(make_pair(*rtnName, bbl_tmp));
		SECTIONS sec_tmp;
		sec_tmp.insert(make_pair(*secName, rtn_tmp));
		images.insert(make_pair(*imgName, sec_tmp));
	}
}

VOID Tracer_Trace(TRACE trace, void*)
{
	RTN *rtn = &TRACE_Rtn(trace);
	if (!RTN_Valid(*rtn)) return;
	const string *rtnName = &RTN_Name(*rtn);

	SEC *sec = &RTN_Sec(*rtn);
	const string *secName = &SEC_Name(*sec);

	IMG *img = &SEC_Img(*sec);
	const string *imgName = &IMG_Name(*img);

	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		BBL_InsertCall(
			bbl,
			IPOINT_BEFORE, (AFUNPTR)BblInstrumentation,
			IARG_PTR, rtnName,
			IARG_PTR, secName,
			IARG_PTR, imgName,
			IARG_ADDRINT, INS_Address(BBL_InsHead(bbl)),
			IARG_ADDRINT, INS_Address(BBL_InsTail(bbl)),
			IARG_END
		);
	}
}

VOID Tracer_Fini(int exitCode, void*)
{
	ofstream fout;
	fout.open("trace.txt");
	for (IMAGES::iterator image = images.begin(); image != images.end(); image++)
	{
		fout << image->first << "\n";
		for (SECTIONS::iterator section = image->second.begin(); section != image->second.end(); section++)
		{
			fout << "\t" << section->first << "\n";
			for (ROUTINES::iterator routine = section->second.begin(); routine != section->second.end(); routine++)
			{
				fout << "\t\t" << routine->first << "\n";
				for (BASIC_BLOCKS::iterator bbl = routine->second.begin(); bbl != routine->second.end(); bbl++)
				{
					fout << "\t\t\t[" << hexstr(bbl->first.first) << "; " << hexstr(bbl->first.second) << "] : " << bbl->second << "\n";
				}
			}
		}
	}
	
	fout << "\nBase Block Count: " << bblCount << "\n";
	fout.close();
}