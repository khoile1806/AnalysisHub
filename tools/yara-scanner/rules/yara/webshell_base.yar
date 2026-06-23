/*
  Seed YARA rules for webshell detection.
  Phase 1 MVP — covers common public PHP/ASP/JSP webshells.
  Replace/extend later with curated set from Neo23x0/signature-base.
*/

rule WS_PHP_GenericEvalBase64
{
    meta:
        author = "ForensicHub"
        description = "PHP eval(base64_decode(...)) loader pattern"
        severity = "high"
    strings:
        $a = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $b = /eval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(/ nocase
    condition:
        (any of them) and filesize < 5MB

}

rule WS_PHP_AssertSuperglobal
{
    meta:
        author = "ForensicHub"
        description = "PHP assert($_POST/GET/REQUEST/...) — classic backdoor stub"
        severity = "high"
    strings:
        $a = /assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/ nocase
    condition:
        (any of them) and filesize < 5MB

}

rule WS_PHP_PregReplaceEval
{
    meta:
        author = "ForensicHub"
        description = "PHP preg_replace with /e modifier (deprecated, abused for code exec)"
        severity = "high"
    strings:
        $a = /preg_replace\s*\([^,]{1,200}\/[a-zA-Z]{0,5}e[a-zA-Z]{0,5}["']/ nocase
    condition:
        (any of them) and filesize < 5MB

}

rule WS_PHP_KnownShellBanner
{
    meta:
        author = "ForensicHub"
        description = "Banner strings of well-known PHP shells"
        severity = "critical"
    strings:
        $c99 = "c99shell" nocase
        $r57 = "r57shell" nocase
        $wso = /WSO\s*\d+(\.\d+)*/ nocase
        $b374k = "b374k" nocase
        $filesman = "FilesMan" nocase
        $alfa = "ALFA TEaM" nocase
        $indox = "IndoXploit" nocase
    condition:
        (any of them) and filesize < 5MB

}

rule WS_PHP_DirectExecSuperglobal
{
    meta:
        author = "ForensicHub"
        description = "Direct command exec from superglobal — high-confidence webshell"
        severity = "critical"
    strings:
        $a = /(system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $b = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        (any of them) and filesize < 5MB

}

rule WS_ASP_EvalRequest
{
    meta:
        author = "ForensicHub"
        description = "ASP Eval/Execute on Request.Form/QueryString"
        severity = "high"
    strings:
        $a = /(Eval|Execute|ExecuteGlobal)\s*\(\s*Request\.(Form|QueryString|Item)/ nocase
        $b = /Server\.CreateObject\s*\(\s*"WScript\.Shell"\s*\)/ nocase
    condition:
        (any of them) and filesize < 5MB

}

rule WS_JSP_RuntimeExecParam
{
    meta:
        author = "ForensicHub"
        description = "JSP Runtime.exec / ProcessBuilder driven by request.getParameter"
        severity = "high"
    strings:
        $a = /Runtime\.getRuntime\s*\(\s*\)\.exec\s*\([^)]{0,200}request\.getParameter/
        $b = /new\s+ProcessBuilder\s*\([^)]{0,200}request\.getParameter/
    condition:
        (any of them) and filesize < 5MB

}

rule WS_Python_EvalExecRequest
{
    meta:
        author = "ForensicHub"
        description = "Python eval/exec wired to incoming request data"
        severity = "high"
    strings:
        $a = /(eval|exec)\s*\(\s*request\.(args|form|values|json)/ nocase
        $b = /subprocess\.(call|run|Popen|check_output)\s*\([^)]{0,200}shell\s*=\s*True[^)]{0,200}request\./
    condition:
        (any of them) and filesize < 5MB

}

rule WS_PHP_ReverseShellSocket
{
    meta:
        author = "ForensicHub"
        description = "PHP reverse shell — outbound TCP socket + shell spawn (proc_open / shell_exec / /bin/sh)"
        severity = "critical"
    strings:
        $fsock  = "fsockopen" nocase
        $popen  = "proc_open" nocase
        $sexec  = "shell_exec" nocase
        $binsh  = /['"]\s*\/bin\/(sh|bash)\s+-i\s*['"]/
    condition:
        ($fsock and ($popen or $sexec or $binsh)) and filesize < 5MB

}

rule WS_PHP_KnownReverseShellBanner
{
    meta:
        author = "ForensicHub"
        description = "Known reverse shell tool identifiers — pentestmonkey php-reverse-shell banner"
        severity = "critical"
    strings:
        $a = "php-reverse-shell" nocase
        $b = "pentestmonkey@pentestmonkey.net" nocase
        $c = "pentestmonkey.net/tools" nocase
    condition:
        (any of them) and filesize < 5MB

}

rule WS_PHP_HardcodedShellSpawn
{
    meta:
        author = "ForensicHub"
        description = "PHP file hardcodes /bin/sh or /bin/bash path for shell spawn"
        severity = "high"
    strings:
        $a = /['"]\s*\/bin\/(sh|bash)\s+-i\s*['"]/
        $b = /\$shell\s*=\s*['"]\/bin\/(sh|bash)/
    condition:
        (any of them) and filesize < 5MB

}

rule WS_PHP_FileDropper
{
    meta:
        author = "ForensicHub"
        description = "PHP writes user-supplied content to disk — file dropper / uploader webshell"
        severity = "high"
    strings:
        $fpc = /file_put_contents\s*\([^,]{0,200},\s*\$_(GET|POST|REQUEST|COOKIE|FILES)/ nocase
        $fw  = /fwrite\s*\([^,]{0,200},\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        (any of them) and filesize < 5MB

}

rule WS_PHP_DynamicFuncCallSuperglobal
{
    meta:
        author = "ForensicHub"
        description = "PHP dynamic function call where function name comes from superglobal: $_GET['f']($_GET['c'])"
        severity = "critical"
    strings:
        $a = /\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,60}\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        (any of them) and filesize < 5MB

}

rule WS_PHP_CallUserFuncSuperglobal
{
    meta:
        author = "ForensicHub"
        description = "call_user_func / call_user_func_array with superglobal as function name or argument"
        severity = "critical"
    strings:
        $a = /call_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $b = /call_user_func(_array)?\s*\(\s*\$\w+\s*,\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        (any of them) and filesize < 5MB

}

rule WS_PHP_ArrayHigherOrderSuperglobal
{
    meta:
        author = "ForensicHub"
        description = "array_map / array_filter / usort abused to invoke arbitrary function from superglobal"
        severity = "critical"
    strings:
        $am = /array_map\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $af = /array_filter\s*\([^,]{0,200},\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $us = /(usort|uasort|uksort)\s*\([^,]{0,200},\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        (any of them) and filesize < 5MB

}

rule WS_PHP_IncludeUserInput
{
    meta:
        author = "ForensicHub"
        description = "PHP include/require from user-controlled superglobal — LFI/RFI to RCE"
        severity = "high"
    strings:
        $a = /\b(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/ nocase
        $b = /\b(include|require)(_once)?\s+\$_(GET|POST|REQUEST|COOKIE|SERVER)/ nocase
    condition:
        (any of them) and filesize < 5MB

}

rule WS_PHP_HexObfuscatedFuncCall
{
    meta:
        author = "ForensicHub"
        description = "PHP function name hidden via hex escape: \"\\x73\\x79\\x73\\x74\\x65\\x6d\" = system"
        severity = "high"
    strings:
        $sys   = /\\x73\\x79\\x73\\x74\\x65\\x6d/   // \x73...\x6d = "system"
        $exec  = /\\x65\\x78\\x65\\x63/              // "exec"
        $eval  = /\\x65\\x76\\x61\\x6c/              // "eval"
        $shell = /\\x73\\x68\\x65\\x6c\\x6c/         // "shell"
        $pack  = /pack\s*\(\s*["']H\*["']/
    condition:
        (any of ($sys, $exec, $eval, $shell) or $pack) and filesize < 5MB

}

rule WS_PHP_PutenvLdPreload
{
    meta:
        author = "ForensicHub"
        description = "PHP putenv LD_PRELOAD bypass — injects shared library then triggers via mail() to gain RCE"
        severity = "critical"
    strings:
        $pe = /putenv\s*\(\s*["']LD_PRELOAD/ nocase
        $ml = /\bmail\s*\(/ nocase
    condition:
        ($pe and $ml) and filesize < 5MB

}

rule WS_ASPX_ProcessStart
{
    meta:
        author = "ForensicHub"
        description = "ASPX/C# executes OS commands via System.Diagnostics.Process — classic ASPX webshell"
        severity = "critical"
    strings:
        $proc = "System.Diagnostics.Process" nocase
        $start = /Process\.Start\s*\(/ nocase
        $new   = /new\s+Process\s*\(\)/ nocase
        $req   = /Request\.(Form|QueryString|Params|\[)/ nocase
    condition:
        (($proc or $start or $new) and $req) and filesize < 5MB

}

rule WS_ASPX_FileWrite
{
    meta:
        author = "ForensicHub"
        description = "ASP ADODB.Stream or FileSystemObject used to write files — dropper payload"
        severity = "high"
    strings:
        $adodb = "ADODB.Stream" nocase
        $fso   = "Scripting.FileSystemObject" nocase
        $save  = /\.SaveToFile\s*\(/ nocase
        $write = /\.Write\s*\(/ nocase
    condition:
        (($adodb or $fso) and ($save or $write)) and filesize < 5MB

}

rule WS_JSP_ScriptEngineEval
{
    meta:
        author = "ForensicHub"
        description = "JSP ScriptEngine / GroovyShell evaluating user-supplied code — dynamic RCE"
        severity = "critical"
    strings:
        $se  = "ScriptEngineManager" nocase
        $gs  = "GroovyShell" nocase
        $bs  = "BshInterpreter" nocase
        $ev  = /\.eval\s*\(/ nocase
        $req = /request\.getParameter/ nocase
    condition:
        (($se or $gs or $bs) and $ev and $req) and filesize < 5MB

}
