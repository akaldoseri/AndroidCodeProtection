<?php

// References:
// https://stackoverflow.com/a/48994119
// https://phpseclib.sourceforge.net/new/x509/tutorial.html
// https://www.geeksforgeeks.org/generating-random-string-using-php/

ini_set('display_errors', true);
error_reporting(E_ALL ^ E_NOTICE);
require __DIR__ . '/vendor/autoload.php';


$n=64;
function getName($n) {
	$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	$randomString = '';

	for ($i = 0; $i < $n; $i++) {
		$index = rand(0, strlen($characters) - 1);
		$randomString .= $characters[$index];
	}

	return $randomString;
}

echo getName($n);
?>

