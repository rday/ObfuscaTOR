<?php
/**
 * @author: Ryan Day <ryanday2@gmail.com>
 * @link: http://ryanday.net/
 * @license MIT
 *
 *
 * The CaptchaFactory class returns a class implementing ICaptcha to the caller.
 * @TODO Have a file format, Name.captcha.php, and have this factory read in 
 *       all captcha libs into an array, and return that way. That will make
 *       it a little easier to put more captcha lib in. Have to think about it...
 */



class CaptchaFactory {
   public function GetCaptcha($id) {
	switch($id) {
		case 1: require_once('WaveCaptcha.php');
			return new WaveCaptcha();
			break;
		case 2: require_once('LineCaptcha.php');
			return new LineCaptcha();
			break;
		case 3: require_once('LetterCaptcha.php');
			return new LetterCaptcha();
			break;
		default: return null;
	}
   }
}
