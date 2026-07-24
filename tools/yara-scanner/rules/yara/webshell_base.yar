/*
  Webshell base rules for AnalysisHub.

  Two design decisions drive the false-positive rate here:

   1. The YARA engine has no per-language routing — unlike the pattern engine it
      evaluates every rule against every scanned file — so each rule is gated on
      a private language-detection rule below. Without that gate a PHP pattern
      happily fires inside a .js, .py or .sh file that merely quotes it.

   2. A single generic token (a banner word, pack('H*'), FileSystemObject) is
      never sufficient on its own. critical/high require either an unambiguous
      marker or two independent indicators; anything weaker is scored medium so
      it lands as a lead rather than a finding.

  Severity feeds scanner/engines/yara_engine.py: critical=95 high=75 medium=55
  low=35, and the scorer adds +5 per additional matching rule.
*/

private rule ah_is_php
{
    strings:
        $open  = "<?php" nocase
        $short = "<?="
        $tag   = /<script\s+language\s*=\s*["']php["']/ nocase
    condition:
        any of them
}

private rule ah_is_asp
{
    strings:
        $page   = /<%@\s*(Page|Import|Assembly|WebHandler)/ nocase
        $runat  = /runat\s*=\s*["']server["']/ nocase
        $sysweb = "System.Web" nocase
        $vbs    = /<%\s*@?\s*Language\s*=/ nocase
    condition:
        any of them
}

private rule ah_is_jsp
{
    strings:
        $page    = /<%@\s*page/ nocase
        $jsptag  = "<jsp:" nocase
        $servlet = "javax.servlet" nocase
        $imp     = /<%@\s*import/ nocase
    condition:
        any of them
}

// ---------------------------------------------------------------- PHP: exec

rule WS_PHP_DirectExecSuperglobal
{
    meta:
        author = "AnalysisHub"
        description = "Direct command exec from a superglobal — high-confidence webshell"
        severity = "critical"
    strings:
        $a = /(system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*@?\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $b = /eval\s*\(\s*@?\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        ah_is_php and any of them and filesize < 5MB
}

rule WS_PHP_DynamicFuncCallSuperglobal
{
    meta:
        author = "AnalysisHub"
        description = "PHP dynamic function call whose name comes from a superglobal: $_GET['f']($_GET['c'])"
        severity = "critical"
    strings:
        $a = /\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,60}\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        ah_is_php and any of them and filesize < 5MB
}

rule WS_PHP_CallUserFuncSuperglobal
{
    meta:
        author = "AnalysisHub"
        description = "call_user_func with a superglobal in the callback position"
        // Only the callback position is a finding. Passing request data as an
        // *argument* to a callback — call_user_func($cb, $_POST['x']) — is
        // ordinary application code and used to trigger this rule at critical.
        severity = "critical"
    strings:
        $a = /call_user_func(_array)?\s*\(\s*@?\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        ah_is_php and any of them and filesize < 5MB
}

rule WS_PHP_ArrayHigherOrderSuperglobal
{
    meta:
        author = "AnalysisHub"
        description = "array_map / array_filter / usort abused to invoke a function named by a superglobal"
        severity = "critical"
    strings:
        // [^,;\n] rather than [^,]: a comma-free run of 200 characters happily
        // spans several statements, so array_filter($_POST) on one line matched
        // the ", $_POST" of an unrelated call_user_func two lines below.
        $am = /array_map\s*\(\s*@?\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $af = /array_filter\s*\([^,;\n]{0,120},\s*@?\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $us = /(usort|uasort|uksort)\s*\([^,;\n]{0,120},\s*@?\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        ah_is_php and any of them and filesize < 5MB
}

rule WS_PHP_AssertSuperglobal
{
    meta:
        author = "AnalysisHub"
        description = "PHP assert($_POST/GET/REQUEST/...) — classic backdoor stub"
        severity = "high"
    strings:
        $a = /assert\s*\(\s*@?\$_(GET|POST|REQUEST|COOKIE|SERVER)/ nocase
    condition:
        ah_is_php and any of them and filesize < 5MB
}

rule WS_PHP_GenericEvalBase64
{
    meta:
        author = "AnalysisHub"
        description = "PHP eval() wrapped around a decoder — packed loader pattern"
        severity = "high"
    strings:
        $a = /eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|hex2bin|convert_uudecode)\s*\(/ nocase
        $b = /eval\s*\(\s*\w+\s*\(\s*(base64_decode|gzinflate|gzuncompress)\s*\(/ nocase
        $c = /(assert|create_function)\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(/ nocase
    condition:
        ah_is_php and any of them and filesize < 5MB
}

rule WS_PHP_PregReplaceEval
{
    meta:
        author = "AnalysisHub"
        description = "PHP preg_replace with the /e modifier (removed in PHP 7, abused for code exec)"
        severity = "high"
    strings:
        $a = /preg_replace\s*\([^,]{1,200}\/[a-zA-Z]{0,5}e[a-zA-Z]{0,5}["']/ nocase
    condition:
        ah_is_php and any of them and filesize < 5MB
}

rule WS_PHP_IncludeUserInput
{
    meta:
        author = "AnalysisHub"
        description = "PHP include/require driven by a request superglobal — LFI/RFI to RCE"
        // $_SERVER is deliberately excluded: include($_SERVER['DOCUMENT_ROOT'].'/x.php')
        // is one of the most common legitimate patterns in PHP applications and
        // was the single largest source of noise from this rule.
        severity = "high"
    strings:
        $a = /\b(include|require)(_once)?\s*\(\s*@?\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $b = /\b(include|require)(_once)?\s+@?\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        ah_is_php and any of them and filesize < 5MB
}

// ------------------------------------------------------------ PHP: obfuscation

rule WS_PHP_HexObfuscatedFuncName
{
    meta:
        author = "AnalysisHub"
        description = "PHP function name hidden behind hex escapes: \\x73\\x79\\x73\\x74\\x65\\x6d = system"
        severity = "high"
    strings:
        $sys   = /\\x73\\x79\\x73\\x74\\x65\\x6d/   // "system"
        $exec  = /\\x65\\x78\\x65\\x63/              // "exec"
        $eval  = /\\x65\\x76\\x61\\x6c/              // "eval"
        $shell = /\\x73\\x68\\x65\\x6c\\x6c/         // "shell"
    condition:
        ah_is_php and any of them and filesize < 5MB
}

rule WS_PHP_PackHexDecoder
{
    meta:
        author = "AnalysisHub"
        description = "pack('H*') hex decoding feeding an execution sink"
        // pack('H*', ...) on its own is ordinary hex handling — it appears in
        // hashing, checksum and binary-protocol code all over legitimate
        // libraries — so it only counts when paired with an execution sink.
        severity = "medium"
    strings:
        $pack = /pack\s*\(\s*["']H\*["']/ nocase
        $sink = /(eval|assert|system|shell_exec|passthru|preg_replace|create_function)\s*\(/ nocase
    condition:
        ah_is_php and $pack and $sink and filesize < 5MB
}

rule WS_PHP_LongEncodedBlobWithSink
{
    meta:
        author = "AnalysisHub"
        description = "Very long base64 blob combined with an execution sink — packed payload"
        severity = "high"
    strings:
        $blob = /[A-Za-z0-9+\/]{600,}={0,2}/
        $sink = /(eval|assert|create_function|preg_replace)\s*\(/ nocase
        $dec  = /(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/ nocase
    condition:
        ah_is_php and $blob and $sink and $dec and filesize < 5MB
}

rule WS_PHP_VariableFunctionObfuscation
{
    meta:
        author = "AnalysisHub"
        description = "Function name assembled from string fragments then called dynamically"
        severity = "medium"
    strings:
        $concat  = /\$\w+\s*=\s*["'][a-z]{1,6}["']\s*\.\s*["'][a-z]{1,6}["']\s*\.\s*["'][a-z]{1,6}["']/ nocase
        $call    = /\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $globals = /\$GLOBALS\s*\[[^\]]{1,40}\]\s*\(\s*\$/ nocase
    condition:
        ah_is_php and (($concat and $call) or $globals) and filesize < 5MB
}

// ------------------------------------------------------------- PHP: known kits

rule WS_PHP_KnownShellBanner
{
    meta:
        author = "AnalysisHub"
        description = "Banner strings unique to well-known PHP shells"
        severity = "critical"
    strings:
        $c99    = "c99shell" nocase
        $r57    = "r57shell" nocase
        $b374k  = "b374k" nocase
        $alfa   = "ALFA TEaM" nocase
        $indox  = "IndoXploit" nocase
        $wsoex  = "wsoEx" nocase
        $wsosec = "wsoSecParam" nocase
        $wsoini = "wso_ini_path" nocase
        $priv8  = "Priv8 Shell" nocase
    condition:
        ah_is_php and any of them and filesize < 5MB
}

rule WS_PHP_WeakShellMarker
{
    meta:
        author = "AnalysisHub"
        description = "Generic file-manager shell markers — only meaningful with a second webshell indicator"
        // "FilesMan" is the action name of the WSO family but also appears in
        // legitimate file managers, and /WSO\s*\d+/ matched the WSO2 product
        // name. Both used to fire at critical on their own; they now need a
        // corroborating capability.
        severity = "medium"
    strings:
        $filesman = "FilesMan" nocase
        $wso      = /WSO\s?\d+(\.\d+)*\s*(shell|web\s?shell)/ nocase
        $cap1     = /\$_(POST|GET|REQUEST)\s*\[\s*["'](a|act|action|cmd|c)["']\s*\]/ nocase
        $cap2     = /(system|shell_exec|passthru|proc_open|popen)\s*\(/ nocase
        $cap3     = "base64_decode" nocase
    condition:
        ah_is_php and ($filesman or $wso) and 1 of ($cap*) and filesize < 5MB
}

rule WS_PHP_ChinaChopperOneLiner
{
    meta:
        author = "AnalysisHub"
        description = "China Chopper style one-liner backdoor"
        severity = "critical"
    strings:
        $a = /@?eval\s*\(\s*\$_(POST|GET|REQUEST)\s*\[\s*["'][^"']{1,20}["']\s*\]\s*\)/ nocase
        $b = /assert\s*\(\s*\$_(POST|GET|REQUEST)\s*\[\s*["'][^"']{1,20}["']\s*\]\s*\)/ nocase
    condition:
        ah_is_php and any of them and filesize < 200KB
}

rule WS_PHP_KnownReverseShellBanner
{
    meta:
        author = "AnalysisHub"
        description = "Known reverse-shell tool identifiers (pentestmonkey php-reverse-shell)"
        severity = "critical"
    strings:
        $a = "php-reverse-shell" nocase
        $b = "pentestmonkey@pentestmonkey.net" nocase
        $c = "pentestmonkey.net/tools" nocase
    condition:
        ah_is_php and any of them and filesize < 5MB
}

rule WS_PHP_ReverseShellSocket
{
    meta:
        author = "AnalysisHub"
        description = "PHP reverse shell — outbound socket paired with an interactive shell spawn"
        // fsockopen alone is a normal HTTP client primitive and shell_exec alone
        // is normal in build tooling; requiring an explicit interactive shell
        // path (or both process primitives) keeps admin panels out of the results.
        severity = "critical"
    strings:
        $fsock = "fsockopen" nocase
        $sock  = /socket_create\s*\(/ nocase
        $popen = "proc_open" nocase
        $sexec = "shell_exec" nocase
        $binsh = /['"]\s*\/bin\/(sh|bash)\s+-i\s*['"]/
    condition:
        ah_is_php and ($fsock or $sock) and ($binsh or ($popen and $sexec)) and filesize < 5MB
}

rule WS_PHP_HardcodedShellSpawn
{
    meta:
        author = "AnalysisHub"
        description = "PHP hardcodes an interactive /bin/sh invocation"
        severity = "high"
    strings:
        $a = /['"]\s*\/bin\/(sh|bash)\s+-i\s*['"]/
        $b = /\$shell\s*=\s*['"]\/bin\/(sh|bash)/
    condition:
        ah_is_php and any of them and filesize < 5MB
}

rule WS_PHP_PutenvLdPreload
{
    meta:
        author = "AnalysisHub"
        description = "PHP LD_PRELOAD bypass — injects a shared object then triggers it via mail()"
        severity = "critical"
    strings:
        $pe = /putenv\s*\(\s*["']LD_PRELOAD/ nocase
        $ml = /\bmail\s*\(/ nocase
    condition:
        ah_is_php and $pe and $ml and filesize < 5MB
}

rule WS_PHP_FileDropperScript
{
    meta:
        author = "AnalysisHub"
        description = "PHP writes request data into a script file — dropper/uploader webshell"
        // The destination extension has to be bound to the write call inside a
        // single regex. Matching ".php" as a separate string let an unrelated
        // include('…/wp-config.php') elsewhere in the file satisfy the rule.
        severity = "high"
    strings:
        $fpc  = /file_put_contents\s*\(\s*["'][^"';\n]{0,120}\.(php|phtml|php5|php7|phar|asp|aspx|jsp)["']\s*,\s*@?\$_(GET|POST|REQUEST|COOKIE|FILES)/ nocase
        $fopen = /fopen\s*\(\s*["'][^"';\n]{0,120}\.(php|phtml|php5|php7|phar|asp|aspx|jsp)["']\s*,\s*["']\s*[wax]/ nocase
        $move = /move_uploaded_file\s*\([^;\n]{0,160}\.(php|phtml|php5|php7|phar|asp|aspx|jsp)["']/ nocase
    condition:
        ah_is_php and any of them and filesize < 5MB
}

rule WS_PHP_UserControlledWritePath
{
    meta:
        author = "AnalysisHub"
        description = "PHP writes to a path taken straight from a request superglobal"
        // Writing request *content* to a fixed file is ordinary (caches, logs,
        // form handlers) and was far too noisy to report. Letting the requester
        // choose the *path* is the part that turns it into arbitrary file write.
        severity = "high"
    strings:
        $a = /(file_put_contents|fopen|copy|rename)\s*\(\s*@?\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $b = /move_uploaded_file\s*\([^;\n]{0,120},\s*@?\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        ah_is_php and any of them and filesize < 5MB
}

// ------------------------------------------------------------------- ASP/ASPX

rule WS_ASP_EvalRequest
{
    meta:
        author = "AnalysisHub"
        description = "ASP Eval/Execute driven by Request data"
        severity = "critical"
    strings:
        $a = /(Eval|Execute|ExecuteGlobal)\s*\(\s*Request\.(Form|QueryString|Item)/ nocase
        $b = /(Eval|Execute|ExecuteGlobal)\s*\(\s*Request\s*\(/ nocase
    condition:
        ah_is_asp and any of them and filesize < 5MB
}

rule WS_ASP_WScriptShell
{
    meta:
        author = "AnalysisHub"
        description = "ASP instantiates WScript.Shell — a command-execution primitive inside a web page"
        severity = "high"
    strings:
        $a = /Server\.CreateObject\s*\(\s*"WScript\.Shell"\s*\)/ nocase
        $b = /CreateObject\s*\(\s*"WScript\.Shell"\s*\)/ nocase
    condition:
        ah_is_asp and any of them and filesize < 5MB
}

rule WS_ASPX_ProcessStart
{
    meta:
        author = "AnalysisHub"
        description = "ASPX page starts an OS process using request-controlled input"
        // The bare "System.Diagnostics.Process" namespace reference was dropped
        // as a trigger: importing it proves nothing, whereas an actual
        // Process.Start together with a Request read is the webshell behaviour.
        severity = "critical"
    strings:
        $start = /Process\.Start\s*\(/ nocase
        $new   = /new\s+Process\s*\(\s*\)/ nocase
        $psi   = "ProcessStartInfo" nocase
        $req   = /Request\.(Form|QueryString|Params|Item|Headers)/ nocase
    condition:
        ah_is_asp and ($start or $new or $psi) and $req and filesize < 5MB
}

rule WS_ASPX_FileWrite
{
    meta:
        author = "AnalysisHub"
        description = "ASP writes a file using request data — dropper payload"
        // ADODB.Stream / FileSystemObject plus a bare ".Write(" matched a large
        // share of ordinary legacy ASP, which writes files for perfectly normal
        // reasons. The request-sourced input is what makes it a dropper.
        severity = "high"
    strings:
        $adodb = "ADODB.Stream" nocase
        $fso   = "Scripting.FileSystemObject" nocase
        $save  = /\.(SaveToFile|Write|WriteLine|CreateTextFile)\s*\(/ nocase
        $req   = /Request\.(Form|QueryString|BinaryRead|Files|Item)/ nocase
    condition:
        ah_is_asp and ($adodb or $fso) and $save and $req and filesize < 5MB
}

// ------------------------------------------------------------------------ JSP

rule WS_JSP_RuntimeExecParam
{
    meta:
        author = "AnalysisHub"
        description = "JSP Runtime.exec / ProcessBuilder driven by request.getParameter"
        severity = "critical"
    strings:
        $a = /Runtime\.getRuntime\s*\(\s*\)\.exec\s*\([^)]{0,200}request\.getParameter/
        $b = /new\s+ProcessBuilder\s*\([^)]{0,200}request\.getParameter/
    condition:
        ah_is_jsp and any of them and filesize < 5MB
}

rule WS_JSP_ScriptEngineEval
{
    meta:
        author = "AnalysisHub"
        description = "JSP ScriptEngine / GroovyShell evaluating user-supplied code"
        severity = "critical"
    strings:
        $se  = "ScriptEngineManager" nocase
        $gs  = "GroovyShell" nocase
        $bs  = "BshInterpreter" nocase
        $ev  = /\.eval\s*\(/ nocase
        $req = /request\.getParameter/ nocase
    condition:
        ah_is_jsp and ($se or $gs or $bs) and $ev and $req and filesize < 5MB
}

rule WS_JSP_EncryptedShellLoader
{
    meta:
        author = "AnalysisHub"
        description = "Behinder/Godzilla style JSP loader — crypto-decoded class defined at runtime"
        severity = "critical"
    strings:
        $cipher = "javax.crypto.Cipher" nocase
        $spec   = "SecretKeySpec" nocase
        $define = /defineClass\s*\(/ nocase
        $loader = "ClassLoader" nocase
        $req    = /request\.(getParameter|getReader|getInputStream)/ nocase
    condition:
        ah_is_jsp and ($cipher or $spec) and ($define or $loader) and $req and filesize < 5MB
}

// --------------------------------------------------------------------- Python

rule WS_Python_EvalExecRequest
{
    meta:
        author = "AnalysisHub"
        description = "Python eval/exec wired to incoming request data"
        severity = "high"
    strings:
        $a = /(eval|exec)\s*\(\s*request\.(args|form|values|json|data)/ nocase
        $b = /subprocess\.(call|run|Popen|check_output)\s*\([^)]{0,200}shell\s*=\s*True[^)]{0,200}request\./
        $c = /os\.(system|popen)\s*\([^)]{0,200}request\.(args|form|values)/ nocase
    condition:
        any of them and filesize < 5MB
}
