<?php
$name = htmlspecialchars($_GET['name'] ?? 'world');
echo "Hello, " . $name;
