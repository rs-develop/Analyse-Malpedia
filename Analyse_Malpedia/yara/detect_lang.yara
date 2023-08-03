rule autohotkey {
    meta:
        author = "Ronny Stoermer"
        date = "15.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/autohotkey/compiled-with-autohotkey.yml"

    strings: 
        $s1 = ">AUTOHOTKEY SCRIPT<"
        $s2 = "AutoHotkeyGUI"
    condition:
        $s1 and $s2
}

rule autoit {
    meta:
        author = "Ronny Stoermer"
        date = "15.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/autoit/compiled-with-autoit.yml"

    strings: 
        $s1 = "AutoIt has detected the stack has become corrupt.\n\nStack corruption typically occurs when either the wrong calling convention is used or when the function is called with the wrong number of arguments.\n\nAutoIt supports the __stdcall (WINAPI) and __cdecl calling conventions.  The __stdcall (WINAPI) convention is used by default but __cdecl can be used instead.  See the DllCall() documentation for details on changing the calling convention."
        $s2 = "AutoIt Error"
        $s3 = ">>>AUTOIT SCRIPT<<<"
        $s4 = ">>>AUTOIT NO CMDEXECUTE<<<"
        $s5 = "#requireadmin"
        $s6 = "#OnAutoItStartRegister"

    condition:
        any of them
}

rule dmd {
    meta:
        author = "Ronny Stoermer"
        date = "15.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/d/compiled-with-dmd.yml"

    strings: 
        $s1 = "._deh"
        $s2 = ".tp"
        $s3 = ".dp"
        $s4 = ".minfo"

    condition:
        all of them
}

rule delphi {
    meta:
        author = "Ronny Stoermer"
        date = "15.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/d/compiled-with-dmd.yml"

    strings:
        $s1 = "Borland C++ - Copyright 2002 Borland Corporation"
        $s2 = "Sysutils::Exception"
        $s3 = "TForm1"
        $s4 = "BORLNDMM.DLL"
        $s5 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $s6 = "Embarcadero Delphi for Win32 compiler"

    condition:
        any of them
}

rule java {
    meta:
        author = "Ronny Stoermer"
        date = "15.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/exe4j/compiled-with-exe4j.yml"

    strings: 
        $s1 = "exe4j_log"
        $s2 = "install4j_log"
        $s3 = "exe4j_java_home"
        $s4 = "install4j"
        $s5 = "exe4j.isinstall4j"
        $s6 = "/com/exe4j/runtime/exe4jcontroller/i"
        $s7 = "/com/exe4j/runtime/winlauncher/i"
        $s8 = "EXE4J_LOG"
        $s9 = "INSTALL4J_LOG"
        $s10 = "EXE4J_JAVA_HOME"
        $s11 = "INSTALL4J"
        $s12 = "EXE4J.ISINSTALL4J"

    condition:
        any of them
}

rule go {
    meta:
        author = "Ronny Stoermer"
        date = "15.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/go/compiled-with-go.yml"

    strings: 
        $a1 = "Go build ID:"
        $a2 = "go.buildid"
        $b3 = "Go buildinf:"
        $b4 = "go1."
        $b5 = "runtime.main"
        $b6 = "main.main"
        $b7 = "runtime.gcWork"

    condition:
        1 of ($a*)
        or 2 of ($b*)
}

rule mingw {
    meta:
        author = "Ronny Stoermer"
        date = "15.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/mingw/compiled-with-mingw-for-windows.yml"
    
    strings:
        $s1 = "Mingw runtime failure:"
        $s2 = "_Jv_RegisterClasses"
    
    condition:
        all of them
}

rule nim {
    meta:
        author = "Ronny Stoermer"
        date = "15.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/nim/compiled-with-nim.yml"
    
    strings:
        $s1 = "NimMain"
        $s2 = "NimMainModule"
        $s3 = "NimMainInner"
        $s4 = "io.nim"
        $s5 = "fatal.nim"
        $s6 = "system.nim"
        $s7 = "alloc.nim"
        $s8 = "osalloc.nim"

    condition:
        any of them
}

rule nuitka {
    meta:
        author = "Ronny Stoermer"
        date = "15.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/nim/compiled-with-nim.yml"
    
    strings:
        $a1 = "nuitka_types_patch"
        $a2 = "O:is_package"
        $a3 = "Error, corrupted constants object"
        $b1 = "NUITKA_ONEFILE_PARENT"
        $b2 = "Error, couldn't runtime expand temporary files."

    condition:
        all of ($a*)
        or all of ($b*)
}

rule perl {
    meta:
        author = "Ronny Stoermer"
        date = "15.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/perl2exe/compiled-with-perl2exe.yml"
    
    strings:
        $a1 = "LoadLibrary"
        $a2 = "FreeLibrary"
        $a3 = /^p2x[a-z0-9]{1,10}\.dll/i
        $b1 = "GetProcAddress"
        $b2 = "RunPerl"

    condition:
        all of ($a*)
        or all of ($b*)
}

rule powershell {
    meta:
        author = "Ronny Stoermer"
        date = "18.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/ps2exe/compiled-with-ps2exe.yml"
    
    strings:
        $a1 = "compiled to the .NET platform"
        $b1 = "PS2EXEApp"
        $b2 = "PS2EXE"
        $b3 = "PS2EXE_Host"
        $c1 = "If you spzzcify thzz -zzxtract option you nzzed to add a filzz for zzxtraction in this way"
        $c2 = "   -zzxtract:\"<filzznamzz>\""

    condition:
        any of ($a1, $b*)
        or any of ($c*)
}

rule python {
    meta:
        author = "Ronny Stoermer"
        date = "18.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/py2exe/compiled-with-py2exe.yml"
    
    strings:
        $a1 = "PY2EXE_VERBOSE"
        $a2 = "getenv"

    condition:
        all of them
}

rule pyarmor {
    meta:
        author = "Ronny Stoermer"
        date = "18.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/pyarmor/compiled-with-pyarmor.yml"
    
    strings:
        $a1 = "pyarmor_runtimesh"
        $a2 = "PYARMOR"
        $a3 = "__pyarmor__"
        $a4 = "PYARMOR_SIGNATURE"

    condition:
        any of them
}

rule rust {
    meta:
        author = "Ronny Stoermer"
        date = "18.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/rust/compiled-with-rust.yml"
    
    strings:
        $a1 = "run with `RUST_BACKTRACE=1` environment variable"
        $a2 = "called `Option::unwrap()` on a `None` value"
        $a3 = "called `Result::unwrap()` on an `Err` value"

    condition:
        any of them
}

rule v {
    meta:
        author = "Ronny Stoermer"
        date = "18.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/v/compiled-with-v.yml"
    
    strings:
        $a1 = "================ V panic ================"
        $a2 = "V_RESOURCE_PATH"
        $b1 = "v_error:"
        $b2 = "v_exit:"
        $b3 = "v_free:"
        $b4 = "v_malloc:"
        $b5 = "v_panic"
        $b6 = "v_realloc"

    condition:
        any of ($a*)
        or 2 of ($b*)
}

rule visualbasic {
    meta:
        author = "Ronny Stoermer"
        date = "18.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/vb/compiled-from-visual-basic.yml"
    
    strings:
        $a1 = "VB5!.*"
        $a2 = "msvbvm60.ThunRTMain"

    condition:
        any of them
}

rule zig {
    meta:
        author = "Ronny Stoermer"
        date = "18.06.2023"
        reference = "https://github.com/mandiant/capa-rules/blob/master/compiler/zig/compiled-with-zig.yml"
    
    strings:
        $a1 = "ZIG_DEBUG_COLOR"
        $a2 = "Panicked during a panic. Aborting."
        $a3 = "error.Unexpected NTSTATUS=0x{x}"
        $a4 = "Unable to dump stack trace: debug info stripped"
        $a5 = "Unable to dump stack trace: Unable to open debug info: {s}"
        $a6 = "Unable to dump stack trace: {s}"
        $a7 = "std.mem.Allocator.alloc"
        $a8 = "_std.os.getenv"
        $a9 = "\\\\.\\pipe\\zig-childprocess-{d}-{d}"

    condition:
        2 of ($a*)
}