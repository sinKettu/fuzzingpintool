/* BBL Trace of images */
#include "FuzzingPinTool.h"
using namespace std;

ofstream TrcFout;
vector<string> imagesList;

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