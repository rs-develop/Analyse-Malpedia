malpedia_sample_mapping = {
    "mappings": {
        "properties": {
            "filename": {
                "type": "keyword"
            },
            "platform": {
                "type": "keyword" 
            },
            "family": {
                "type": "keyword"
            },
            "language": {
                "type": "keyword" 
            },
            "linker": {
                "type": "keyword"
            },
            "linker_name": {
                "type": "keyword"
            },
            "sha256": {
                "type": "keyword"
            },
            "dumpsize": {
                "type": "integer"
            },
            "has_mz_magic": {
                "type": "boolean"
            },
            "has_pe_magic": {
                "type": "boolean"
            },
            "has_dos_string": {
                "type": "boolean"
            },
            "pe_check": {
                "type": "boolean"
            },
            "pefile": {
                "type": "boolean"
            },
            "bitness": {
                "type": "integer"
            },
            "is32": {
                "type": "boolean"
            },
            "num_sections": {
                "type": "integer"
            },
            "timestamp": {
                "type": "date",
                "format": "epoch_second"
            },
            "timestamp_valid": {
                "type": "boolean"
            },
            "year": {
                "type": "integer"
            },
            "month": {
                "type": "integer"
            },
            "day": {
                "type": "integer"
            },
            "os_required": {
                "type": "keyword"
            },
            "attribution": {
                "type": "keyword"
            },
            "alt_names": {
                "type": "keyword"
            },
            "is_attributed": {
                "type": "boolean"
            },
            "family_activity": {
                "type": "integer"
            },
            "family_first_seen": {
                "type": "integer"
            },
            "family_last_seen": {
                "type": "integer"
            },
            "sample_status": {
                "type": "keyword"
            },
            "vt_data_available": {
                "type": "boolean"
            },
            "vt_first_submission": {
                "type": "date",
                "format": "epoch_second"
            },
            "vt_year": {
                "type": "integer"
            },
            "timestamp_diff_days": {
                "type": "integer"
            },
        }
    }
}

malpedia_family_mapping = {
    "mappings": {
        "properties": {
            "family": {
                "type": "keyword"
            },
            "sample_count": {
                "type": "integer"
            },
            "language_count": {
                "type": "integer"
            },
            "languages": {
                "type": "keyword" 
            },
            "platform": {
                "type": "keyword"
            },
            "linker_count": {
                "type": "integer"
            },
            "linker": {
                "type": "keyword"
            },
            "bitness": {
                "type": "integer"
            },
            "pefile": {
                "type": "boolean"
            },
            "family_activity": {
                "type": "integer"
            },
            "year": {
                "type": "integer"
            },
            "has_invalid_timestamps": {
                "type": "boolean"
            },
        }
    }
}

malpedia_rel_data_mapping = {
    "mappings": {
        "properties": {
            "year": {
                "type": "integer"
            },
            "rel_32": {
                "type": "double"
            },
            "rel_64": {
                "type": "double"
            },
            "rel_dumpsize": {
                "type": "double"
            },
            "vt_submission_vs_timestamp": {
                "type": "double"
            },
            "c/c++": {
                "type": "double"
            },
            "dotnet": {
                "type": "double"
            },
            "go": {
                "type": "double"
            },
            "rust": {
                "type": "double"
            },
            "delphi": {
                "type": "double"
            },
            "assembler": {
                "type": "double"
            },
            "nim": {
                "type": "double"
            },
            "visualbasic": {
                "type": "double"
            },
            "aix": {
                "type": "double"
            },
            "swift": {
                "type": "double"
            },
            "java": {
                "type": "double"
            },
            "java script": {
                "type": "double"
            },
            "php": {
                "type": "double"
            },
            "powershell": {
                "type": "double"
            },
            "python": {
                "type": "double"
            },
            "v": {
                "type": "double"
            },
            "pyarmor": {
                "type": "double"
            },
            "perl": {
                "type": "double"
            },
            "nuitka": {
                "type": "double"
            },
            "dmd": {
                "type": "double"
            },
            "autoit": {
                "type": "double"
            },
            "autohotkey": {
                "type": "double"
            },
            "zig": {
                "type": "double"
            },
            "purebasic_4x": {
                "type": "double"
            },
        }
    }
}