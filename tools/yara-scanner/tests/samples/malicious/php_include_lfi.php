<?php
// LFI via include
include($_GET['page']);
require_once($_POST['file']);
