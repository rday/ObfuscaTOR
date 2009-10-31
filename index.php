<?php
/**
 * This is mean to be a quick example of how to use the library. For a more
 * indepth example you can look at the ObfuscaTOR wordpress plugin.
 *
 * @author: Ryan Day <ryanday2@gmail.com>
 * @link: http://ryanday.net/
 * @license MIT
 */

require_once('CaptchaFactory.php');
header('Content-Type: image/jpeg');

//1: Wave Captcha
//2: Line Captcha
//3: Letter Captcha
$r = rand(1,3);

// Grab random captcha class
$captcha = CaptchaFactory::GetCaptcha($r);

// Set some properties
$captcha->SetHeight(100);
$captcha->SetWidth(300);

// Set our text to the bridge information, we use bridges.torproject.org as our source
$captcha->SetText(getBridges());

// Display the jpeg
echo $captcha->CreateJPEG();



/* NOTE: When using bridges.torproject.org please consider using some trivial
	cache mechanism to avoid many unecessary requests to the site! */
function getBridges() {
        $filestore = file_get_contents('https://bridges.torproject.org/');
        preg_match_all('/^bridge (.*?)$/m', $filestore, $match);
        $text = "";
        foreach($match[1] as $val) $text .= $val . "\n";
        return $text;
}
