#!/usr/bin/python
import os
import re
import sys
import json
import argparse

from utility import convertUnixTimestamp, getDateObjectFromTimestamp, getCurrentYear
from multiprocessing import Pool, cpu_count

import tqdm

from Identifier import Identifier
from process_peheader import PEHeaderCheck

class MalpediaAnalyser():

    _malpediaRepositoryPath = ""
    _outputDir              = ""
    _vtCacheDB              = None
    _fileQueue              = []
    _samplesAnalysisResults = []
    _famalyAnalysisResults  = {}
    _cachedVtData           = None
    _analyseAllSamples      = False
    _packedSampleCount      = 0
    _malpediaPlatform       = ["aix", "apk", "asp", "elf", "fas", "ios", "jar", "js", "osx", 
                               "php", "ps1", "py, symbian", "vbs", "win"]
    _relStatistics          = {}
    _relAnalysisResults     = {}
    

    def __init__(self, malpedia_repo_path_src, output_path_src, vt_cache_db_path_src, analyse_all_samples_src) -> None:
        self._malpediaRepositoryPath = malpedia_repo_path_src
        self._outputDir = output_path_src + os.path.sep
        if vt_cache_db_path_src:
            self._loadVtCacheDB(vt_cache_db_path_src)
        self._analyseAllSamples = analyse_all_samples_src
        # Get file list
        self._getFiles()


    def _getFamilyName(self, file):
        family_name = ""
        abs_path = os.path.abspath(file)
        for folder in abs_path.split("/")[::-1]:
            if folder == "malpedia":
                break
            family_name = folder
        return family_name


    def _getSampleVersion(self, input_path, family):
        family_name = ""
        abs_path = os.path.dirname(os.path.abspath(input_path))
        for folder in abs_path.split("/")[::-1]:
            if folder == family or folder == "modules":
                break
            family_name = folder
        return family_name


    def _getMalpediaFilePath(self, input_path):
        egg = 'malpedia/'
        abs_path = os.path.abspath(input_path)
        pos = abs_path.index(egg)
        malpedia_filepath = abs_path[pos + len(egg):]
        return malpedia_filepath


    def _loadVtCacheDB(self, vt_cache_db_path):
        if os.path.exists(vt_cache_db_path):
            cacheFileObj = open(vt_cache_db_path, "r")
            try:
                self._cachedVtData = json.load(cacheFileObj)
            except ValueError:
                print("Database file is not valid or empty.")
            cacheFileObj.close()


    def _getVtData(self, hash):
        results = dict()
        results['vt_data_available'] = False
        results['vt_first_submission'] = 0
        if self._cachedVtData:
            if hash in self._cachedVtData:
                results['vt_data_available'] = True
                results['vt_first_submission'] = self._cachedVtData[hash]['first_submission_date']
        return results


    def _getJsonInfoContent(self, filepath):
        with open(filepath, 'r') as file:
            return json.load(file)


    def _getFiles(self):
        #finished_reports = getAllReportFilenames(args.output_path)
        dump_file_pattern = re.compile("dump7?_0x[0-9a-fA-F]{8,16}")
        unpacked_file_pattern = re.compile("_unpacked(_x64)?$")
        familyDir = ""

        # Find all targets (everything) to disassemble in malpedia.
        for root, subdir, files in sorted(os.walk(self._malpediaRepositoryPath)):
            if ".git" in root:
                continue
            if "win." not in root and not self._analyseAllSamples:
                continue
            elif any(name in root for name in self._malpediaPlatform):
                if len(self._malpediaRepositoryPath) < len(root):
                    if familyDir:
                        if not os.path.split(familyDir)[1] in root.split("/"): 
                            familyDir = self._malpediaRepositoryPath + os.sep + \
                                root.split("/")[len(self._malpediaRepositoryPath.split("/"))]
                    else:
                        familyDir = self._malpediaRepositoryPath + os.sep + \
                            root.split("/")[len(self._malpediaRepositoryPath.split("/"))]
                else:
                    familyDir = root
                
                for filename in sorted(files):
                    if not (re.search(unpacked_file_pattern, filename) or re.search(dump_file_pattern, filename)):
                        self._packedSampleCount = self._packedSampleCount + 1
                        continue
                    filepath = root + os.sep + filename
                    malpedia_sample = {
                        "filename": filename,
                        "filepath": filepath,
                        "malpedia_path": self._malpediaRepositoryPath,
                        "json_info": familyDir + os.sep + os.path.basename(os.path.normpath(familyDir) + ".json")
                    }
                    self._fileQueue.append(malpedia_sample)
    

    def _getMalpediaPlatform(self, filepath):
        res_platform = "unknown"
        for platform in self._malpediaPlatform:
            if platform in filepath:
                res_platform = platform
                break
        return res_platform
    

    def _getSampleStatus(self, filename):
        res = "unknown"
        if "dump" in filename:
            res = "dumped"
        elif "unpacked" in filename:
            res = "unpacked"
        else:
            res = "Packed"
        return res


    def _getMalwareActivity(self, activities):
        firstSeen = 0
        lastSeen  = 0
        activity  = 0

        for entry in activities:
            year = int(entry.split(':')[1][0:4])
            if firstSeen > 0:
                if firstSeen > year:
                    firstSeen = year
            else:
                firstSeen = year

            if lastSeen > 0:
                if lastSeen < year:
                    lastSeen = year
            else:
                lastSeen = year
            if (lastSeen - firstSeen) == 0:
                activity = 1
            else:
                activity = lastSeen - firstSeen

        return firstSeen, lastSeen, activity


    def _work(self, file):
        sampleResDict = dict()

        filename = file['filename']
        filepath = file['filepath']

        # Init analyser
        identifier = Identifier()
        peChecker = PEHeaderCheck()

        # Results for the sample dict
        sampleResDict['filename'] = filename
        sampleResDict['platform'] = self._getMalpediaPlatform(filepath)

        jsonInfoContent = self._getJsonInfoContent(file['json_info'])
        if not jsonInfoContent['common_name'] or "Unidentified" in jsonInfoContent['common_name']:
            sampleResDict['family'] = self._getFamilyName(filepath)
        else:
            sampleResDict['family'] = jsonInfoContent['common_name']
        
        sampleResDict.update(identifier.identifyLanguage(filepath, sampleResDict['platform'])) # Identify code and language of the sample
        sampleResDict.update(peChecker.process(filepath))                                      # Extract PE header information
        
        sampleResDict['attribution'] = jsonInfoContent['attribution']
        sampleResDict['alt_names'] = jsonInfoContent['alt_names']
        if sampleResDict['attribution']:
            sampleResDict['is_attributed'] = True
        else:
            sampleResDict['is_attributed'] = False

        if 'library_entries' in jsonInfoContent:
            firstseen, lastseen, activity = self._getMalwareActivity(jsonInfoContent['library_entries'])
            sampleResDict['family_activity']   = activity
            sampleResDict['family_first_seen'] = firstseen
            sampleResDict['family_last_seen']  = lastseen
        else:
            sampleResDict['family_activity']   = 0
            sampleResDict['family_first_seen'] = 0
            sampleResDict['family_last_seen']  = 0

        sampleResDict['sample_status'] = self._getSampleStatus(filename)

        sampleResDict.update(self._getVtData(sampleResDict["sha256"]))
        if sampleResDict['vt_data_available']:
            dt = getDateObjectFromTimestamp(sampleResDict['vt_first_submission'])
            sampleResDict['vt_year']  = int(dt.year)
            sampleResDict['vt_month'] = int(dt.month)
            sampleResDict['vt_day']   = int(dt.day)
            sampleResDict['timestamp_diff_days']  = (getDateObjectFromTimestamp(sampleResDict['vt_first_submission']) - getDateObjectFromTimestamp(sampleResDict['timestamp'])).days
        else:
            sampleResDict['vt_year']  = 0
            sampleResDict['vt_month'] = 0
            sampleResDict['vt_day']   = 0
            sampleResDict['timestamp_diff_days']  = 0

        return sampleResDict
    

    def _analyseFamilys(self):
        for item in self._samplesAnalysisResults:
            if item['family'] in self._famalyAnalysisResults:
                self._famalyAnalysisResults[item['family']]['sample_count'] = self._famalyAnalysisResults[item['family']]['sample_count'] + 1
                if item['language'] not in self._famalyAnalysisResults[item['family']]['languages']:
                    self._famalyAnalysisResults[item['family']]['languages'].append(item['language'])
                    self._famalyAnalysisResults[item['family']]['language_count'] = self._famalyAnalysisResults[item['family']]['language_count'] + 1
                if item['platform'] not in self._famalyAnalysisResults[item['family']]['platform']:
                    self._famalyAnalysisResults[item['family']]['platform'].append(item['platform'])
                    self._famalyAnalysisResults[item['family']]['platform_count'] = self._famalyAnalysisResults[item['family']]['platform_count'] + 1
                for sample_linker in item['linker_name']:
                    if sample_linker not in self._famalyAnalysisResults[item['family']]['linker']:
                        self._famalyAnalysisResults[item['family']]['linker'].append(sample_linker)
                        self._famalyAnalysisResults[item['family']]['linker_count'] = self._famalyAnalysisResults[item['family']]['linker_count'] + 1
                if item['bitness'] not in self._famalyAnalysisResults[item['family']]['bitness']:
                    self._famalyAnalysisResults[item['family']]['bitness'].append(item['bitness'])
                    if 0 in self._famalyAnalysisResults[item['family']]['bitness']:
                        self._famalyAnalysisResults[item['family']]['bitness'].remove(0)
                if item['pefile'] not in self._famalyAnalysisResults[item['family']]['pefile']:
                    self._famalyAnalysisResults[item['family']]['pefile'].append(item['pefile'])
                if item['family_activity'] > self._famalyAnalysisResults[item['family']]['family_activity']:
                    self._famalyAnalysisResults[item['family']]['family_activity'] = item['family_activity']
                if item['family_first_seen'] < self._famalyAnalysisResults[item['family']]['family_first_seen']:
                    self._famalyAnalysisResults[item['family']]['family_first_seen'] = item['family_first_seen']
                if item['family_last_seen'] > self._famalyAnalysisResults[item['family']]['family_last_seen']:
                    self._famalyAnalysisResults[item['family']]['family_last_seen'] = item['family_last_seen']
                if item['year'] < self._famalyAnalysisResults[item['family']]['year']:
                    self._famalyAnalysisResults[item['family']]['year'] = item['year']
                if not item['timestamp_valid']:
                    self._famalyAnalysisResults[item['family']]['has_invalid_timestamps'] = True
                
                
            else: 
                year = 1970
                if item['year'] == 1970:
                    year = convertUnixTimestamp(item['vt_first_submission']).year
                self._famalyAnalysisResults[item['family']] = {
                    'sample_count': 1,
                    'language_count': 1,
                    'languages': [item['language']],
                    'platform': [item['platform']],
                    'platform_count': 1,
                    'linker_count': len(item['linker_name']),
                    'linker': item['linker_name'],
                    'bitness': [item['bitness']],
                    'pefile': [item['pefile']],
                    'family_activity': item['family_activity'],
                    'family_first_seen': item['family_first_seen'],
                    'family_last_seen': item['family_last_seen'],
                    'year': year,
                    'has_invalid_timestamps' : item['timestamp_valid'],
                } 


    def _extractRelativeData(self, sampleDict):
        if sampleDict['pefile']:
            if sampleDict['bitness'] == 32:
                if sampleDict['year'] in self._relStatistics:
                    if '32' in self._relStatistics[sampleDict['year']]:
                        self._relStatistics[sampleDict['year']]['32'] = self._relStatistics[sampleDict['year']]['32'] + 1
                    else:
                        self._relStatistics[sampleDict['year']]['32'] = 1
                else:
                    self._relStatistics[sampleDict['year']] = {'32':1}
            if sampleDict['bitness'] == 64:
                if sampleDict['year'] in self._relStatistics:
                    if '64' in self._relStatistics[sampleDict['year']]:
                        self._relStatistics[sampleDict['year']]['64'] = self._relStatistics[sampleDict['year']]['64'] + 1
                    else:
                        self._relStatistics[sampleDict['year']]['64'] = 1
                else:
                    self._relStatistics[sampleDict['year']] = {'64':1}

        if sampleDict['dumpsize']:
            if sampleDict['year'] in self._relStatistics:
                if 'dumpsize' in self._relStatistics[sampleDict['year']]:
                    self._relStatistics[sampleDict['year']]['dumpsize'].append(int(sampleDict['dumpsize']))
                else:
                    self._relStatistics[sampleDict['year']]['dumpsize'] = [sampleDict['dumpsize']]
            else:
                self._relStatistics[sampleDict['year']] = {'dumpsize':[sampleDict['dumpsize']]}

        if not sampleDict['language'] == "unknown":
            if sampleDict['year'] in self._relStatistics:
                if 'language' in self._relStatistics[sampleDict['year']]:
                    if sampleDict['language'] in self._relStatistics[sampleDict['year']]['language']:
                        self._relStatistics[sampleDict['year']]['language'][sampleDict['language']] = self._relStatistics[sampleDict['year']]['language'][sampleDict['language']] + 1
                    else:
                        self._relStatistics[sampleDict['year']]['language'].update({sampleDict['language']:1})
                else:
                    self._relStatistics[sampleDict['year']]['language'] = {sampleDict['language']:1}
            else:
                self._relStatistics[sampleDict[sampleDict['year']]] = {sampleDict['language']:1}

        if sampleDict['vt_data_available']:
            if sampleDict['vt_year'] > 1990 and sampleDict['year'] > 1990 and sampleDict['year'] < (getCurrentYear() + 1):
                if sampleDict['year'] in self._relStatistics:
                    if 'vt_first_submission' in self._relStatistics[sampleDict['year']]:
                        self._relStatistics[sampleDict['year']]['vt_first_submission'].append(int(sampleDict['vt_first_submission']))
                    else:
                        self._relStatistics[sampleDict['year']]['vt_first_submission'] = [sampleDict['vt_first_submission']]
                    if 'timestamp' in self._relStatistics[sampleDict['year']]:
                        self._relStatistics[sampleDict['year']]['timestamp'].append(int(sampleDict['timestamp']))
                    else:
                        self._relStatistics[sampleDict['year']]['timestamp'] = [sampleDict['timestamp']]
                else:
                    self._relStatistics[sampleDict['year']] = {'vt_first_submission':[sampleDict['vt_first_submission']]}
                    self._relStatistics[sampleDict['year']] = {'timestamp':[sampleDict['timestamp']]}
                     
    
    def _analyseRelativeData(self):
        for year in self._relStatistics:
            if year != 1970 and year <= (getCurrentYear() + 1):
                self._relAnalysisResults[year] = {
                    'rel_32' : 0,
                    'rel_64' : 0,
                    'rel_dumpsize' : 0,
                    'vt_submission_vs_timestamp' : 0,
                    'c/c++' : 0,
                    'dotnet' : 0,
                    'go' : 0,
                    'rust' : 0,
                    'delphi' : 0,
                    'assembler' : 0,
                    'nim' : 0,
                    'visualbasic' : 0,
                    'aix' : 0,
                    'swift' : 0,
                    'java' : 0,
                    'java script' : 0,
                    'php' : 0,
                    'powershell' : 0,
                    'python' : 0,
                    'visualbasic' : 0,
                    'visualbasic script' : 0,
                    'v' : 0,
                    'pyarmor' : 0,
                    'perl' : 0,
                    'nuitka' : 0,
                    'dmd' : 0,
                    'autoit' : 0,
                    'autohotkey' : 0,
                    'zig' : 0,
                    'purebasic_4x' : 0,
                }

                if '32' in self._relStatistics[year]:
                    val32 = self._relStatistics[year]['32']
                if '64' in self._relStatistics[year]:
                    val64 = self._relStatistics[year]['64']

                self._relAnalysisResults[year].update({'rel_32' : val32 / (val32 + val64)})
                self._relAnalysisResults[year].update({'rel_64' : val64 / (val64 + val32)})
                
                if 'dumpsize' in self._relStatistics[year]:
                    actualDumpsizeSum = 0
                    lastDumpSizeSum   = 0
                    relDumpSize       = 0 
                    
                    actualDumpsizeSum = sum(self._relStatistics[year]['dumpsize']) / len(self._relStatistics[year]['dumpsize'])
                    if (int(year) - 1) in self._relStatistics:
                        if 'dumpsize' in self._relStatistics[int(year) - 1]:
                            lastDumpSizeSum = sum(self._relStatistics[int(year) - 1]['dumpsize']) / len(self._relStatistics[int(year) - 1]['dumpsize'])        
                        relDumpSize = ((actualDumpsizeSum - lastDumpSizeSum) / lastDumpSizeSum)
                    self._relAnalysisResults[year].update({'rel_dumpsize' : relDumpSize})

                if 'language' in self._relStatistics[year]:
                    for name in self._relStatistics[year]['language']:
                        if (int(year) - 1) in self._relStatistics:
                            if 'language' in self._relStatistics[int(year) - 1]:
                                if name in self._relStatistics[int(year) - 1]['language']:
                                    actualLangSum = self._relStatistics[year]['language'][name]
                                    lastLangSum = self._relStatistics[int(year) - 1]['language'][name]
                                    self._relAnalysisResults[year].update({name : ((actualLangSum - lastLangSum) / lastLangSum)})
                            else:
                                actualLangSum = self._relStatistics[year]['language'][name]
                                self._relAnalysisResults[year].update({name : ((actualLangSum - 0) / actualLangSum)})

                if 'timestamp' in self._relStatistics[year]:
                    if 'vt_first_submission' in self._relStatistics[year]:
                        if len(self._relStatistics[year]['timestamp']) == len(self._relStatistics[year]['vt_first_submission']):
                            
                            res = []
                            for i in range(min(len(self._relStatistics[year]['timestamp']), len(self._relStatistics[year]['vt_first_submission']))):
                                timestamp = self._relStatistics[year]['timestamp'][i]
                                vt_timestamp = self._relStatistics[year]['vt_first_submission'][i]
    
                                diff = vt_timestamp - timestamp
                                diff_percent = (diff / timestamp)
    
                                res.append(diff_percent)

                            average = sum(res) / len(res)
                            self._relAnalysisResults[year].update({'vt_submission_vs_timestamp' : average})


    def analyse(self):
        # Enable Pooling for faster analysis
        if not self._analyseAllSamples:
           with Pool(cpu_count() - 1) as pool:
               for sample_results in tqdm.tqdm(pool.imap_unordered(self._work, self._fileQueue), total=len(self._fileQueue)):
                   self._extractRelativeData(sample_results)
                   self._samplesAnalysisResults.append(sample_results)
        
        else:
        # Single processing for debugging or vt enrichment
            #i = 1
            for file in self._fileQueue:
                sample_results = self._work(file)
                self._extractRelativeData(sample_results)
                self._samplesAnalysisResults.append(sample_results)
             #   i = i + 1
              #  if i == 800:
               #     break
            
        print("Analysing relative data ...")
        self._analyseRelativeData()
        print("Done!")

        print("Analysing Families ...")
        self._analyseFamilys()
        print("Done!")


    def writeReport(self):
        print("Writing Reports ...")
        with open(self._outputDir + "malpedia_sample_analysis.json", 'w') as samples:
            for item in self._samplesAnalysisResults:
                json.dump(item, samples)
                samples.writelines("\n")
        with open(self._outputDir + "malpedia_family_analysis.json", 'w') as families:
            for item in self._famalyAnalysisResults:
                familyExportDict = {'family':item}
                for entry in self._famalyAnalysisResults[item]:
                    familyExportDict.update({entry:self._famalyAnalysisResults[item][entry]})
                json.dump(familyExportDict, families)
                families.writelines("\n")
        with open(self._outputDir + "malpedia_relative_analysis.json", 'w') as relative_data:
            for item in self._relAnalysisResults:
                relative_data_dict = {'year':item}
                for entry in self._relAnalysisResults[item]:
                    relative_data_dict.update({entry:self._relAnalysisResults[item][entry]})
                json.dump(relative_data_dict, relative_data)
                relative_data.writelines("\n")
        

    def getPackedSamplesCount(self):
        return self._packedSampleCount


if __name__ == "__main__":

    parser = argparse.ArgumentParser(prog='Analyse Malpedia', description='Analysis all samples of the Malpedia repository')
    parser.add_argument('path_to_samples', help="Path to the Malpedia repository")
    parser.add_argument('-c', '--vt_cache_file', help="Path to the VT cache database (optional)")
    parser.add_argument('-o', '--output_path', help="Output Path for the result DB (default is same dir as the script)", default=os.getcwd())
    parser.add_argument('--all', help='Analyse all samples. Default is windows pe only', const=True, nargs='?')

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args=parser.parse_args()

    analyser = MalpediaAnalyser(args.path_to_samples, args.output_path, args.vt_cache_file, args.all)
    analyser.analyse()
    analyser.writeReport()

    print("Info packed sample count: ", analyser.getPackedSamplesCount(), "; Packed samples will not processed!")
    print("DONE, shutting down")