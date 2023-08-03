#!/usr/bin/python
import sys
import os
import re
import json
import argparse
from typing import Any
import requests
from datetime import datetime
from configparser import ConfigParser

class VT():
    CONFIG =  os.path.dirname(os.path.realpath(__file__)) + '/config.ini'
    headers = {}

    def __init__(self) -> None:
        config = ConfigParser()
        config.read(self.CONFIG)
        if not 'virustotal' in config:
            config['virustotal'] = {}
        if not 'apikey' in config['virustotal']:
            key = input('please enter apikey for virustotal: ').lower().strip()
            config['virustotal']['apikey'] = key
            with open(self.CONFIG, 'w') as configfile:
                config.write(configfile)
        key = config['virustotal']['apikey'].lower()
        self.headers = {
            'x-apikey': key,
        }


    def get_report(self, hash):
        response = requests.get('https://www.virustotal.com/api/v3/files/' + hash, headers=self.headers)
        return response.status_code, response.text
    

    def get_attributes(self, data):
        d = json.loads(data)
        if 'data' in d:
            data = d['data']
            if 'attributes' in data:
                return data['attributes']

class CacheVT():

    _vt_object       = None
    _samplesPath     = str()
    _sampleHashList  = []
    _vtCacheFilePath = str()
    _vtCacheFileObj  = None
    _cachedVtData    = dict()
    _newHashCount    = 0
    _oldHashCount    = 0
    _maxRequests     = 0

    def __init__(self, vt_cache_file_Path_src) -> None:
        self._vtCacheFilePath = vt_cache_file_Path_src
        self._vt_object = VT()


    def initCachingProcess(self, samples_path_src, max_requests_src):
        self._samplesPath = samples_path_src
        self._maxRequests = max_requests_src
        self._initCacheFileIfNotExists()


    def _loadCacheFileData(self):
        if os.path.exists(self._vtCacheFilePath):
            vtOldCacheFileObj = open(self._vtCacheFilePath, "r")
            try:
                self._cachedVtData = json.load(vtOldCacheFileObj)
            except ValueError:
                print("Database file is not valid or empty.")
                exit()
            vtOldCacheFileObj.close()


    def _initCacheFileIfNotExists(self):
        if os.path.exists(self._vtCacheFilePath):
            self._loadCacheFileData()
            self._oldHashCount = len(self._cachedVtData)
            print("Loaded old cache file with " + str(self._oldHashCount) + " entries.")
            os.rename(self._vtCacheFilePath, os.path.dirname(self._vtCacheFilePath) + "/" + datetime.today().strftime('%Y-%m-%d-%H:%M:%S')+"_cached_vt_data.json")
            self._vtCacheFileObj = open(self._vtCacheFilePath, "w")
        else:
            self._vtCacheFileObj = open(self._vtCacheFilePath, "w")


    def _addEntry(self, hash):
        status, vt_report = self._vt_object.get_report(hash)
        if status == 200:
            self._cachedVtData[hash] = self._vt_object.get_attributes(vt_report)
            print("Added new hash: " + hash)
            self._newHashCount = self._newHashCount + 1
        elif status == 429:
            print("Quota exceeted! Aborting query process.")
            return False
        elif status == 404:
            print("File not found on VT: " + hash)
        else:
            print("Unhandled status: " + str(status) + "; hash: " + hash)
        return True


    def searchForHash(self, hash) -> str:
        self._loadCacheFileData()
        print(str(len(self._cachedVtData)) + " hashes in database.\n")
        if hash in self._cachedVtData:
            return self._cachedVtData[hash]
        else:
            return "Hash not found in database"


    def getHashesFromSamples(self):
        for root, subdir, files in sorted(os.walk(self._samplesPath)):
            if ".git" in root:
                continue
            if not "win." in root:
                continue
            for filename in sorted(files):
                match = re.search(r'^[a-fA-F0-9]{64}$', filename)
                if match:
                    self._sampleHashList.append(match.group(0))


    def getVtData(self):
        if not self._sampleHashList:
            print("No hashes to request from VT found.")
            exit()
        for hash in self._sampleHashList:
            if self._cachedVtData:
                if not hash in self._cachedVtData:
                    try:
                        if self._newHashCount == self._maxRequests:
                            break
                        if self._addEntry(hash) == False:
                            break
                    except KeyboardInterrupt:
                        print("User interrupt")
                        break
                    except:
                        print("Unknown error on hash: " + hash)
                else:
                    print("Hash already known: " + hash)
            else:
                try:
                    if self._addEntry(hash) == False:
                        break
                except KeyboardInterrupt:
                    print("User interrupt")
                    break
                except:
                    print("Error on hash: " + hash)


    def finishProcessing(self):
        json.dump(self._cachedVtData, self._vtCacheFileObj)
        print("Writing new VT data.")
        print("Old cached hashes count: " + str(self._oldHashCount))
        print("New cached hashes count: " + str(len(self._cachedVtData)))
        print("Added " + str(len(self._cachedVtData) - self._oldHashCount ) + " entries")


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(prog='Cache VT Data', description='Caches VT metadata to given samples')
    parser.add_argument('-p,','--path_to_samples', help="Path to the samples which will be requested on VT")
    parser.add_argument('-m', '--max_requests', help="Max requests to not exeed quota (default 500)", default=500, type=int)
    parser.add_argument('-c', '--cache_file', help="Path to existing cache file which will be extend (default cached_vt_data.json)", default="cached_vt_data.json")
    parser.add_argument('-s', '--search', help="Print data to a specific hash and exit", type=str)
    
    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args=parser.parse_args()
    CacheVtObj = CacheVT(args.cache_file)

    if args.search:
        print(CacheVtObj.searchForHash(args.search))

    elif args.path_to_samples:
        if os.path.exists(args.path_to_samples):
            CacheVtObj.initCachingProcess(args.path_to_samples, args.max_requests)
            CacheVtObj.getHashesFromSamples()
            CacheVtObj.getVtData()
            CacheVtObj.finishProcessing()
        else:
            print("Sample path does not exist.")
    else:
        print("No Sample path specified.")