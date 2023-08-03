#!/usr/bin/env python3

import os
import pefile

from utility import get_word, get_dword, CompareResult, read_byte_content_from_file, get_pe_offset, check_pe, get_string, check_bitness, getDateObjectFromTimestamp

class LoadPEFileError(Exception):
    pass

IMAGE_SCN_TYPE_NO_PAD = 0x00000008
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_LNK_OTHER = 0x00000100
IMAGE_SCN_LNK_INFO = 0x00000200
IMAGE_SCN_LNK_REMOVE = 0x00000800
IMAGE_SCN_LNK_COMDAT = 0x00001000
IMAGE_SCN_GPREL = 0x00008000
IMAGE_SCN_MEM_PURGEABLE = 0x00020000
IMAGE_SCN_MEM_16BIT = 0x00020000
IMAGE_SCN_MEM_LOCKED = 0x00040000
IMAGE_SCN_MEM_PRELOAD = 0x00080000
IMAGE_SCN_ALIGN_1BYTES = 0x00100000
IMAGE_SCN_ALIGN_2BYTES = 0x00200000
IMAGE_SCN_ALIGN_4BYTES = 0x00300000
IMAGE_SCN_ALIGN_8BYTES = 0x00400000
IMAGE_SCN_ALIGN_16BYTES = 0x00500000
IMAGE_SCN_ALIGN_32BYTES = 0x00600000
IMAGE_SCN_ALIGN_64BYTES = 0x00700000
IMAGE_SCN_ALIGN_128BYTES = 0x00800000
IMAGE_SCN_ALIGN_256BYTES = 0x00900000
IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000
IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
IMAGE_SCN_MEM_SHARED = 0x10000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


class PEHeaderCheck():

    def __init__(self):
        self._buffer = None
        self._path = None
        self._sha256 = None

        self.pe_standard_sections = {
            # Uninitialized data (free format)
            ".bss": IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
            # CLR metadata that indicates that the object file contains managed code
            ".cormeta": IMAGE_SCN_LNK_INFO,
            # Initialized data (free format)
            ".data": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
            # Generated FPO debug information (object only, x86 architecture only, and now obsolete)
            ".debug$F": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE,
            # Precompiled debug types (object only)
            ".debug$P": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE,
            # Debug symbols (object only)
            ".debug$S": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE,
            # Debug types (object only)
            ".debug$T": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE,
            # Linker options
            ".drective": IMAGE_SCN_LNK_INFO,
            # Export tables
            ".edata": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            # Import tables
            ".idata": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
            # Includes registered SEH (image only) to support IDL attributes. 
            ".idlsym": IMAGE_SCN_LNK_INFO,
            # Exception information
            ".pdata": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            # Read-only initialized data
            ".rdata": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            # Image relocations
            ".reloc": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE,
            # Resource directory
            ".rsrc": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            # GP-relative uninitialized data (free format)
            ".sbss": IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_GPREL,
            # GP-relative initialized data (free format)
            ".sdata": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_GPREL,
            # GP-relative read-only data (free format)
            ".srdata": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_GPREL,
            # Registered exception handler data (free format and x86/object only)
            ".sxdata": IMAGE_SCN_LNK_INFO,
            # Executable code (free format)
            ".text": IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            # Thread-local storage (object only)
            ".tls": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
            # Thread-local storage (object only)
            ".tls$": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
            # GP-relative initialized data (free format and for ARM, SH4, and Thumb architectures only)
            ".vsdata": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
            # Exception information (free format)
            ".xdata": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        }


    def process(self, path_to_executable_or_dump):
        self._path = path_to_executable_or_dump
        self._read_file_content()

        result = dict()
        self._sha256 = self._path.rsplit('/')[-1].split("_")[0]
        result["sha256"] = self._sha256
        result["dumpsize"] = len(self._buffer)
        result["has_mz_magic"] = self._check_mz_magic()
        result["has_pe_magic"] = self._check_pe_magic()
        result["has_dos_string"] = self._check_dos_string()
        result["pe_check"] = check_pe(self._buffer)
        result["pefile"] = self._check_pe_file()
        result["bitness"] = check_bitness(self._buffer)
        result["is32"] = self._check_is_32_bit()
        result["num_sections"] = self._check_num_sections()
        #result["sections"] = self._check_sections()
        result["timestamp_valid"] = self._check_timestamp_valid()
        result["timestamp"] = self._check_timestamp()
        dt = getDateObjectFromTimestamp(result["timestamp"])
        result["year"] = int(dt.year)
        result["month"] = int(dt.month)
        result["day"] = int(dt.day)
        result["os_required"] = self._check_os_required()
        result.update(self._get_header_information())
        result.update(self._check_com_descriptor())
        return result


    def _read_file_content(self):
        if not os.path.exists(self._path):
            raise FileNotFoundError("the file(path) you provided does not exist: {}".format(self._path))
        try:
            self._buffer = read_byte_content_from_file(self._path)
        except IOError as io_error:
            raise LoadPEFileError(str(io_error))


    def _get_pe_offset(self):
        if check_pe(self._buffer):
            return get_pe_offset(self._buffer)


    def _check_dos_string(self):
        dos_string_variants = [
            b"This program cannot be run in DOS mode",
            b"This program must be run under Win32",
            b"This program must be run under Win64",
            b"This program requires Win32"
        ]
        return any([dos_string in self._buffer[:0x400] for dos_string in dos_string_variants])


    def _check_mz_magic(self):
        return self._buffer[0:2] == b"MZ"


    def _check_pe_magic(self):
        pe_offset = self._get_pe_offset()
        if pe_offset and len(self._buffer) >= pe_offset + 2:
            return self._buffer[pe_offset:pe_offset + 2] == b"PE"
        return False


    def _check_pe_file(self):
        try:
            _ = pefile.PE(data=self._buffer)
            return True
        except pefile.PEFormatError:
            return False
        except UnboundLocalError:
            return False


    def _check_is_32_bit(self):
        bitness = check_bitness(self._buffer)

        if bitness == 32:
            return True
        else:
            return False
        

    def _check_num_sections(self):
        num_sections = 0
        pe_offset = self._get_pe_offset()
        if pe_offset and len(self._buffer) >= pe_offset + 8:
            num_sections = get_word(self._buffer, pe_offset + 6)
        return num_sections


    def _check_sections(self):
        sections = 0
        pe_offset = self._get_pe_offset()
        if pe_offset and len(self._buffer) >= pe_offset + 0x400:
            sections = []
            file_characteristics_offset = pe_offset + 0x18
            file_characteristics = get_word(self._buffer, file_characteristics_offset)
            base_offset = 0
            if file_characteristics == 0x10b:
                base_offset = pe_offset + 0xF8
            elif file_characteristics == 0x20b:
                base_offset = pe_offset + 0x108
            num_sections = get_word(self._buffer, pe_offset + 6)
            # cap the sections to 256 to avoid issues with tampered headers
            num_sections = min(256, num_sections)
            for section_index in range(num_sections):
                section_start = base_offset + 0x28 * section_index
                section_name = get_string(self._buffer[section_start:section_start + 8], 0)
                section_vsize = get_dword(self._buffer, section_start + 0x8)
                section_vaddr = get_dword(self._buffer, section_start + 0xC)
                section_flags = get_dword(self._buffer, section_start + 0x24)
                is_well_known_name = section_name in self.pe_standard_sections
                has_correct_flags = False
                if is_well_known_name:
                    has_correct_flags = section_flags & self.pe_standard_sections[section_name] == self.pe_standard_sections[section_name]
                # break if we otherwise encounter an empty entry
                if all(not value for value in [section_vsize, section_vaddr, section_flags]):
                    break
                sections.append((section_name, is_well_known_name, section_vsize, section_vaddr, has_correct_flags))
        return sections


    def _check_timestamp(self):
        timestamp = 0
        pe_offset = self._get_pe_offset()
        if pe_offset and len(self._buffer) >= pe_offset + 12:
            data = get_dword(self._buffer, pe_offset + 8)
            if data not in [0, 708992537] and data < 2147483647:
                timestamp = data
        return timestamp


    def _check_timestamp_valid(self):
        timestamp_valid = False
        pe_offset = self._get_pe_offset()
        if pe_offset and len(self._buffer) >= pe_offset + 12:
            data = get_dword(self._buffer, pe_offset + 8)
            if data not in [0, 708992537] and data < 2147483647:
                timestamp_valid = True
        return timestamp_valid


    def _check_os_required(self):
        os_required = ""
        pe_offset = self._get_pe_offset()
        if pe_offset and len(self._buffer) >= pe_offset + 68:
            optional_header_offset = pe_offset + 24
            major = get_word(self._buffer, optional_header_offset + 40)
            minor = get_word(self._buffer, optional_header_offset + 42)
            os_required = "{}.{}".format(major, minor)
        return os_required


    def _get_header_information(self):
        if not check_bitness(self._buffer):
            return {}
        result = dict()
        pe_offset = self._get_pe_offset()
        file_characteristics_offset = pe_offset + 0x16
        #image_subsystem_offset = pe_offset + 0x5c
        #image_dll_characteristics_offset = pe_offset + 0x5e
        #image_dll_characteristics = get_word(self._buffer, image_dll_characteristics_offset)
        #image_subsystem = get_word(self._buffer, image_subsystem_offset)
        is_dll = bool(get_word(self._buffer, file_characteristics_offset) & 0x2000)
        #has_nx = bool(image_dll_characteristics & 0x40)
        #has_aslr = bool(image_dll_characteristics & 0x100)
        #has_safeseh = not bool(image_dll_characteristics & 0x400)
        result["dll"] = is_dll
        result["exe"]  = not is_dll
        #result["nx"] = has_nx
        #result["aslr"] = has_aslr
        #result["safeseh"] = has_safeseh
        #result["nx_aslr"] = has_nx and has_aslr
        #result["exe_nx"] = not is_dll and has_nx
        #result["exe_aslr"] = not is_dll and has_aslr
        #result["exe_nx_aslr"] = not is_dll and has_nx and has_aslr
        #result["dll_nx"] = is_dll and has_nx
        #result["dll_aslr"] = is_dll and has_aslr
        #result["dll_nx_aslr"] = is_dll and has_nx and has_aslr
        #result["subsystem"] = image_subsystem
        return result


    def _check_data_directories(self):
        result = {}
        if not check_bitness(self._buffer):
            return result
        pe_offset = self._get_pe_offset()
        file_characteristics_offset = pe_offset + 0x18
        file_characteristics = get_word(self._buffer, file_characteristics_offset)
        base_offset = 0
        if file_characteristics == 0x10b:
            base_offset = pe_offset + 0x78
        elif file_characteristics == 0x20b:
            base_offset = pe_offset + 0x88
        else:
            return result
        index_offset = 0
        for directory_name in self._data_directories:
            directory_descriptor_offset = get_dword(self._buffer, base_offset + index_offset)
            result["has_dd_" + directory_name] = 0 < directory_descriptor_offset < len(self._buffer)
            index_offset += 8
        return result


    def _check_com_descriptor(self):
        result = {}
        if not check_bitness(self._buffer):
            return result
        pe_offset = self._get_pe_offset()
        file_characteristics_offset = pe_offset + 0x18
        file_characteristics = get_word(self._buffer, file_characteristics_offset)
        field_offset = 0
        if file_characteristics == 0x10b:
            field_offset = 0xE8
        elif file_characteristics == 0x20b:
            field_offset = 0xF8
        image_dir_com_descriptor_offset = pe_offset + field_offset
        com_descriptor_offset = get_dword(self._buffer, image_dir_com_descriptor_offset)
        if field_offset > 0 and len(self._buffer) - 8 > com_descriptor_offset > 0:
            result["has_com_descriptor"] = True
            result["com_major_version"] = get_word(self._buffer, com_descriptor_offset + 4)
            result["com_minor_version"] = get_word(self._buffer, com_descriptor_offset + 6)
        else:
            result["has_com_descriptor"] = False
        return result