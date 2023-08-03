#!/usr/bin/python

import os
import yara

from utility import get_pe_offset, check_bitness, get_dword, get_word, read_byte_content_from_file, check_pe

class Identifier(object):

    _compiledYaraLanguageDetection     = None
    _compiledYaraCompilerDetection_x86 = None
    _compiledYaraCompilerDetection_x64 = None
    _buffer                            = None

    def __init__(self) -> None:
        self._compileYaraRules()


    def _compileYaraRules(self):
        
        # Compile and load language detection
        self._compiledYaraLanguageDetection = yara.compile(filepath=os.path.dirname(__file__) + "/yara/detect_lang.yara")

        # Compile and load compiler detection x86
        self._compiledYaraCompilerDetection_x86 = yara.compile(filepath=os.path.dirname(__file__) + "/yara/compilers_x86.yara")

        # Compile and load compiler detection x64
        self._compiledYaraCompilerDetection_x64 = yara.compile(filepath=os.path.dirname(__file__) + "/yara/compilers_x64.yara")


    def _check_linker(self):
        linker = "unknown"
        if check_pe(self._buffer):
            pe_offset = get_pe_offset(self._buffer)
            if pe_offset and len(self._buffer) >= pe_offset + 28:
                optional_header_offset = pe_offset + 24
                major = self._buffer[optional_header_offset + 2]
                minor = self._buffer[optional_header_offset + 3]
                linker = "{}.{}".format(major, minor)
                if linker == "2.25":
                    if self._check_delphi_linker():
                        linker = "2.25d"
        return linker
    

    def _check_delphi_linker(self):
        if b"CODE" in self._buffer[:0x400] and b"DATA" in self._buffer[:0x400]:
            return True
        if b"\x07TObject" in self._buffer[:0x2000] or b"\x0AWideString" in self._buffer[:0x2000]:
            return True
        return False


    def _check_linker_name(self, linker):
        linker_name = ""
        compiler_map = {
            "0.0": ("-", "Likely nulled"),
            "0.40": ("GoAsm", "GoLink 0.40"),
            "1.70": ("FASM", "Flat Assembler 1.70"),
            "1.71": ("FASM", "Flat Assembler 1.71"),
            "2.50": ("MASM", "Polink"),
            "5.12": ("MASM", "MIL 5.12"),
            "2.23": ("MinGW", "gcc 2.23"),
            "2.24": ("MinGW", "gcc 2.24"),
            "2.25": ("MinGW", "gcc 2.25"),
            "2.27": ("MinGW", "gcc 2.27"),
            "2.55": ("MinGW", "LCC Linker 2.55"),
            "2.56": ("MinGW", "gcc 2.56"),
            "2.64": ("MinGW", "gcc 2.64"),
            "3.0": ("Go", "Go Compiler 3.0"),
            "2.25d": ("Borland Delphi", "Turbo Linker 2.25"),
            "5.0": ("Borland C++", "Borland C++ 5.0"),
            "6.0": ("MSVC", "MSC1200 (VC6)"),
            "7.0": ("MSVC", "MSC1300 (VS 2002)"),
            "7.10": ("MSVC", "MSC1310 (VS 2003)"),
            "8.0": ("MSVC", "MSC1400 (VS 2005)"),
            "9.0": ("MSVC", "MSC1500 (VS 2008)"),
            "10.0": ("MSVC", "MSC1600 (VS 2010)"),
            "11.0": ("MSVC", "MSC1700 (VS 2012)"),
            "12.0": ("MSVC", "MSC1800 (VS 2013)"),
            "14.0": ("MSVC", "MSC1900 (VS 2015)"),
            "14.10": ("MSVC", "MSC1910 (VS 2017)"),
            "14.11": ("MSVC", "MSC1911 (VS 2017 Update 4)"),
            "14.12": ("MSVC", "MSC1912 (VS 2017 Update 4)"),
            "14.13": ("MSVC", "MSC1913 (VS 2017 Update 6)"),
            "14.14": ("MSVC", "MSC1914 (VS 2017 Update 7)"),
            "14.15": ("MSVC", "MSC1915 (VS 2017 Update 8)"),
            "14.16": ("MSVC", "MSC1916 (VS 2017 Update 9)"),
            "14.20": ("MSVC", "MSC1920 (VS 2019)"),
            "14.21": ("MSVC", "MSC1921 (VS 2019 Update 1)"),
            "14.24": ("MSVC", "MSC1924 (VS 2019 Update 4)"),
            "14.25": ("MSVC", "MSC1925 (VS 2019 Update 5)"),
            "14.26": ("MSVC", "MSC1926 (VS 2019 Update 6)"),
            "14.27": ("MSVC", "MSC1927 (VS 2019 Update 7)"),
            "14.28": ("MSVC", "MSC1928 (VS 2019 Update 8)"),
            "14.30": ("MSVC", "MSC1930 (VS 2022)"),
            "14.31": ("MSVC", "MSC1931 (VS 2022 Update 1)"),
            "14.32": ("MSVC", "MSC1932 (VS 2022 Update 2)"),
            "4.0": ("-", "forged?"),
            "4.2": ("-", "forged?"),
            "4.4": ("-", "forged?"),
            "5.2": ("-", "forged?"),
            "5.4": ("-", "forged?"),
            "6.2": ("-", "forged?"),
            "7.2": ("-", "forged?"),
            "7.3": ("-", "forged?"),
            "8.2": ("-", "forged?"),
            "8.3": ("-", "forged?"),
            "8.4": ("-", "forged?"),
            "9.1": ("-", "forged?"),
            "0.58": ("Unknown", "Upack fragment?"),
            "1.0": ("Unknown", "fragment?"),
            "1.68": ("Unknown", " UPX fragment?"),
            "76.111": ("Unknown", "Upack fragment?"),
            "48.0": ("Unknown", ".net 48.0"),
            "80.0": ("Unknown", ".net 80.0"),
        }
        if linker is not None and linker in compiler_map:
            linker_name = compiler_map[linker]
        return list(linker_name)


    def _identifyDotnet(self):
        if not check_bitness(self._buffer):
            return "unknown"
        pe_offset = get_pe_offset(self._buffer)
        file_characteristics_offset = pe_offset + 0x18
        file_characteristics = get_word(self._buffer, file_characteristics_offset)
        field_offset = 0
        if file_characteristics == 0x10b:
            field_offset = 0xE8
        elif file_characteristics == 0x20b:
            field_offset = 0xF8
        image_dir_com_descriptor_offset = pe_offset + field_offset
        #print(image_dir_com_descriptor_offset)
        # only .NET binaries will feature a COM dscription in the data directory
        com_descriptor_offset = get_dword(self._buffer, image_dir_com_descriptor_offset)
        if field_offset > 0 and len(self._buffer) - 8 > com_descriptor_offset > 0:
            return "dotnet"
        return "unknown"


    def identifyLanguage(self, filepath, malpedia_platform):
        resDict = {
            "language": "unknown",
            "linker": "unknown",
            "linker_name": [] 
        }
        self._buffer = read_byte_content_from_file(filepath)

        # Get linker information
        linker = self._check_linker()
        if linker:
            resDict["linker"] = linker
            resDict["linker_name"] = self._check_linker_name(linker)

        # Check for dotnet
        resDict["language"] = self._identifyDotnet()

        # Check for other languages
        if resDict["language"] == "unknown":
            matches = self._compiledYaraLanguageDetection.match(filepath)
            if matches:
                resDict["language"] = matches[0].rule
            else:
                matches = self._compiledYaraCompilerDetection_x86.match(filepath)
                if matches:
                    resDict["language"] = matches[0].rule
                else:
                    matches = self._compiledYaraCompilerDetection_x64.match(filepath)
                    if matches:
                        resDict["language"] = matches[0].rule

            # Check Language by linker
            if resDict["language"] == "unknown":
                for name in resDict["linker_name"]:
                    if name == "MSVC":
                        resDict["language"] = "c/c++"
                        break
                    elif name == "FASM":
                        resDict["language"] = "assembler"
                        break
                    elif name == "MASM":
                        resDict["language"] = "assembler"
                        break
                    elif name == "Borland Delphi":
                        resDict["language"] = "delphi"
                        break
                    elif name == "MinGW":
                        resDict["language"] = "c/c++"
                        break
                    elif name == "Borland C++":
                        resDict["language"] = "c/c++"
                        break

            # Set lenguage by malpedia_platform 
            if resDict["language"] == "unknown":
                if malpedia_platform == "aix":
                    resDict["language"] = "assembler"
                elif malpedia_platform == "apk":
                    resDict["language"] = "java"
                elif malpedia_platform == "asp":
                    resDict["language"] = "dotnet"
                elif malpedia_platform == "fas":
                    resDict["language"] = "assembler"
                elif malpedia_platform == "ios":   
                    resDict["language"] = "swift"
                elif malpedia_platform == "jar":   
                    resDict["language"] = "java"
                elif malpedia_platform == "js":   
                    resDict["language"] = "java script"
                elif malpedia_platform == "php":   
                    resDict["language"] = "php"
                elif malpedia_platform == "ps1":   
                    resDict["language"] = "powershell"
                elif malpedia_platform == "py":   
                    resDict["language"] = "python"
                elif malpedia_platform == "vbs":   
                    resDict["language"] = "visualbasic script"

            # Additional check for Languages
            if resDict["language"] != "unknown" and resDict["language"] != "c/c++":
                if any(lang in resDict["language"] for lang in ["msvc", "intel", "mingw", "gcc", "lcc"]):
                    resDict["language"] = "c/c++"
                elif "delphi" in resDict["language"]:
                    resDict["language"] = "delphi"
                elif "ms_visual_basic" in resDict["language"]:
                    resDict["language"] = "visualbasic"
                elif "fasm" in resDict["language"]:
                    resDict["language"] = "assembler"
                elif "f2ko" in resDict["language"]:
                    resDict["language"] = "visualbasic"
                elif "masm" in resDict["language"]:
                    resDict["language"] = "assembler"
                elif "purebasic" in resDict["language"]:
                    resDict["language"] = "purebasic"
                elif "pyarmor" in resDict["language"]:
                    resDict["language"] = "python"
                elif "pascal" in resDict["language"]:
                    resDict["language"] = "pascal"

        return resDict