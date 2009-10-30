<?php

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
