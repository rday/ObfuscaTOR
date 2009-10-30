<?php

/*
   api: php
   title: Easy_CAPTCHA
   description: highly configurable, user-friendly and accessible CAPTCHA
   version: 2.0
   author: milki
   url: http://freshmeat.net/p/captchaphp
   config:
      <const name="CAPTCHA_PERSISTENT" value="1"  type="boolean" title="persistent cookie" description="sets a cookie after user successfully solved it, spares further captchas for a few days" />
      <const name="CAPTCHA_NEW_URLS" value="1"  type="boolean" title="new URLs only Javascript" description="uses Javascript detection to engage CAPTCHA only if a new URL was entered into any input box" />
      <const name="CAPTCHA_AJAX" value="1" type="boolean" title="AJAX quickcheck" description="verfies the solution (visually) while user enters it" />
      <const name="CAPTCHA_IMAGE_SIZE" value="200x60" type="string" regex="\d+x\d+" title="image size" description="height x width of CAPTCHA image" />
      <const name="CAPTCHA_INVERSE" value="1"  type="boolean" title="inverse color" description="make captcha white on black" />
      <const name="CAPTCHA_PIXEL" value="1" type="multi" multi="1=single pixel|2=greyscale 2x2|3=smooth color" title="smooth drawing" description="image pixel assembly method and speed" />
      <const name="CAPTCHA_ONCLICK_HIRES" value="1" type="boolean" title="onClick-HiRes" description="reloads a finer resolution version of the CAPTCHA if user clicks on it" />
      <const name="CAPTCHA_TIMEOUT" value="5000" type="string" regex="\d+" title="verification timeout" description="in seconds, maxiumum time to elaps from CAPTCHA display to verification" />
   type: intercept
   category: antispam
   priority: optional


   This library operates CAPTCHA form submissions, to block spam bots and
   alike. It is easy to hook into existing web sites and scripts. It also
   tries to be "smart" and more user-friendly.
   
   While the operation logic and identifier processing are extremley safe,
   this is a "weak" implementation. Specifically targetted and tweaked OCR
   software could overcome the visual riddle. And if enabled, the textual
   or mathematical riddles are rather simple to overcome if attacked.
   Generic spambots are however blocked already with the default settings.
   
   PRINT captcha::form()
     emits the img and input fields for inclusion into your submit <form>
   
   IF (captcha::solved())
     tests for a correctly entered solution on submit, returns true if ok
   
   Temporary files are created for tracking, verification and basic data
   storage, but will get automatically removed once a CAPTCHA was solved
   to prevent replay attacks. Additionally this library uses "AJAX" super
   powers *lol* to enhance usability. And a short-lasting session cookie
   is also added site-wide, so users may only have to solve the captcha
   once (can be disabled, because that's also just security by obscurity).
   
   Public Domain, available via http://freshmeat.net/p/captchaphp
*/


/*****
 *
 *   NOTE:  The above notice is the original license in full.  There are some instructions included in the
 *          license that may no longer apply due to the changes I've made to have this lib meet the interface
 *          requirements.
 *          - ryan day
 */

require_once('ICaptcha.class.php');
#-- behaviour
define("CAPTCHA_PERSISTENT", 1);     // cookie-pass after it's solved once (does not work if headers were already sent on innovocation of captcha::solved() check)
define("CAPTCHA_NEW_URLS", 1);       // force captcha only when URLs submitted
define("CAPTCHA_AJAX", 1);           // visual feedback while entering letters
define("CAPTCHA_LOG", 0);            // create /tmp/captcha/log file
define("CAPTCHA_NOTEXT", 0);         // disables the accessible text/math riddle

#-- look
define("CAPTCHA_IMAGE_TYPE", 2);     // 1=wave, 2=whirly
define("CAPTCHA_INVERSE", 1);        // white or black(=1)
define("CAPTCHA_IMAGE_SIZE", "600x160");  // randomly adapted a little
define("CAPTCHA_INPUT_STYLE", "height:46px; font-size:34px; font-weight:450;");
define("CAPTCHA_PIXEL", 1);          // set to 2 for smoother 2x2 grayscale pixel transform
define("CAPTCHA_ONCLICK_HIRES", 1);  // use better/slower drawing mode on reloading

#-- solving
define("CAPTCHA_FUZZY", 0.65);       // easier solving: accept 1 or 2 misguessed letters
define("CAPTCHA_TRIES", 5);          // maximum failures for solving the captcha
define("CAPTCHA_AJAX_TRIES", 25);    // AJAX testing limit (prevents brute-force cracking via check API)
define("CAPTCHA_MAXPASSES", 2);      // 2 passes prevent user annoyment with caching/reload failures
define("CAPTCHA_TIMEOUT", 5000);     // (in seconds/2) = 3:00 hours to solve a displayed captcha
define("CAPTCHA_MIN_CHARS", 2);      // how many letters to use
define("CAPTCHA_MAX_CHARS", 70);

#-- operation
define("CAPTCHA_TEMP_DIR", (@$_SERVER['TEMP'] ? $_SERVER['TEMP'] : '/tmp') . "/captcha/");
define("CAPTCHA_PARAM_ID", "__ec_i");
define("CAPTCHA_PARAM_INPUT", "__ec_s");
define("CAPTCHA_BGCOLOR", 0xFFFFFF);   // initial background color (non-inverse, white)
define("CAPTCHA_SALT", ",e?c:7<");
#define("CAPTCHA_DATA_URLS", 0);     // RFC2397-URLs exclude MSIE users
define("CAPTCHA_FONT_DIR", dirname(__FILE__));
define("CAPTCHA_BASE_URL", "http://$_SERVER[SERVER_NAME]:$_SERVER[SERVER_PORT]/" . substr(realpath(__FILE__), strlen(realpath($_SERVER["DOCUMENT_ROOT"]))));


/* simple API */
class LetterCaptcha implements ICaptcha {

   function LetterCaptcha() { $this->c = new easy_captcha(); }
   function CreateJPEG() {
      return $this->c->image->jpeg();
   }

   function Save() {
   }

   function SetHeight($height) { $this->c->image->height = $height; }
   function SetWidth($width) { $this->c->image->width = $width; }
   function SetText($text) { $this->c->image->solution = $text; }

}

/* base logic and data storare */
class easy_captcha {

   #-- init data
   function easy_captcha($id=NULL, $ignore_expiration=0) {

      #-- load
      if (($this->id = $id) or ($this->id = preg_replace("/[^-,.\w]+/", "", @$_REQUEST[CAPTCHA_PARAM_ID]))) {
         $this->load();
      }

         $this->generate();
   }

   #-- create solutions
   function generate() {
      #-- init
      srand(microtime() + time()/2 - 21017);

      #-- captcha processing info
      $this->sent = 0;
      $this->tries = CAPTCHA_TRIES;  // 5
      $this->ajax_tries = CAPTCHA_AJAX_TRIES;  // 25
      $this->passed = 0;
      $this->maxpasses = CAPTCHA_MAXPASSES;   // 2
      $this->failures = 0;
      $this->shortcut = array();
      $this->grant = 0;  // unchecked access

      #-- mk IMAGE/GRAPHIC
     /* $this->image = (CAPTCHA_IMAGE_TYPE <= 1)
                   ? new easy_captcha_graphic_image_waved()
                   : new easy_captcha_graphic_image_disturbed();*/
      $this->image = new easy_captcha_graphic_image_disturbed();
   }
}

#-- image captchas, base and utility code
class easy_captcha_graphic extends easy_captcha {

   #-- config
   function easy_captcha_graphic($x=NULL, $y=NULL) {
      $this->width = 300;
      $this->height = 100;
      $this->inverse = CAPTCHA_INVERSE;
      $this->bg = CAPTCHA_BGCOLOR;
      $this->maxsize = 0xFFFF;
      $this->quality = 66;
   }

   #-- return a single .ttf font filename
   function font() {
      $fonts = array(/*"COLLEGE.ttf"*/);
      $fonts += glob(CAPTCHA_FONT_DIR."/*.ttf");
      return $fonts[rand(0,count($fonts)-1)];
   }

   #-- return GD color
   function random_color($a,$b) {
      $R = $this->inverse ? 0xFF : 0x00;
      return imagecolorallocate($this->img, rand($a,$b)^$R, rand($a,$b)^$R, rand($a,$b)^$R);
   }
   function rgb ($r,$g,$b) {
      $R = $this->inverse ? 0xFF : 0x00;
      return imagecolorallocate($this->img, $r^$R, $g^$R, $b^$R);
   }


   #-- generate JPEG output
   function output() {
      ob_start();
      ob_implicit_flush(0);
        imagejpeg($this->img, "", $this->quality);
        $jpeg = ob_get_contents();
      ob_end_clean();
      imagedestroy($this->img);
      unset($this->img);
      return($jpeg);
   }
}

class easy_captcha_graphic_image_disturbed extends easy_captcha_graphic {


   /* returns jpeg file stream with unscannable letters encoded 
      in front of colorful disturbing background
   */
   function jpeg() {
      #-- step by step
      $this->create();
      $this->background_lines();
      $this->background_letters();
      $this->text();
      return $this->output();
   }


   #-- initialize in-memory image with gd library
   function create() {
      $this->img = imagecreatetruecolor($this->width, $this->height);
      imagefilledrectangle($this->img, 0,0, $this->width,$this->height, $this->random_color(222, 255));

      #-- encolour bg
      $wd = 20;
      $x = 0;
      while ($x < $this->width) {
         imagefilledrectangle($this->img, $x, 0, $x+=$wd, $this->height, $this->random_color(222, 255));
         $wd += max(10, rand(0, 20) - 10);
      }
   }


   #-- make interesting background I, lines
   function background_lines() {
      $c1 = rand(150, 185);
      $c2 = rand(195, 230);
      $wd = 4;
      $w1 = 0;
      $w2 = 0;
      for ($x=0; $x<$this->width; $x+=(int)$wd) {
         if ($x < $this->width) {   // verical
            imageline($this->img, $x+$w1, 0, $x+$w2, $this->height-1, $this->random_color($c1++,$c2));
         }
         if ($x < $this->height) {  // horizontally ("y")
            imageline($this->img, 0, $x-$w2, $this->width-1, $x-$w1, $this->random_color($c1,$c2--));
         }
         $wd += rand(0,8) - 4;
         if ($wd < 1) { $wd = 2; }
         $w1 += rand(0,8) - 4;
         $w2 += rand(0,8) - 4;
         if (($x > $this->height) && ($y > $this->height)) {
            break;
         }
      }
   }


   #-- more disturbing II, random letters
   function background_letters() {
      $limit = rand(30,90);
      for ($n=0; $n<$limit; $n++) {
         $letter = "";
         do {
            $letter .= chr(rand(31,125)); // random symbol
         } while (rand(0,1));
         $size = rand(5, $this->height/2);
         $half = (int) ($size / 2);
         $x = rand(-$half, $this->width+$half);
         $y = rand(+$half, $this->height);
         $rotation = rand(60, 300);
         imagettftext($this->img, $size, $rotation, $x, $y, $this->random_color(130, 240), $this->font(), $letter);
      }
   }


   #-- add the real text to it
   function text() {
      $phrase = $this->solution;
      $len = strlen($phrase);
      $w1 = 10;
      $w2 = $this->width / ($len+1);
      $line = 0;
      $iX = 1;
      for ($p=1; $p<=$len; $p++) {
         $letter = $phrase[$p];
         $size = rand(18, 23);
         $half = (int) $size / 2;
         $rotation = rand(-3, 3);
         $iY = $line * $size;
         $y = $iY + rand(28, 33);
         $x = ($iX * $size) + rand(12,17);
         $iX++;
         if( $phrase[$p] == "\n" ) {
		$line++;
		$iX = 1;
	 }
         //$w1 += rand(-$this->width/90, $this->width/40);  // @BUG: last char could be +30 pixel outside of image
         $font = $this->font();
         list($r,$g,$b) = array(rand(30,99), rand(30,99), rand(30,99));
         imagettftext($this->img, $size, $rotation, $x+1, $y, $this->rgb($r*2,$g*2,$b*2), $font, $letter);
         imagettftext($this->img, $size, $rotation, $x, $y-1, $this->rgb($r,$g,$b), $font, $letter);
      }
   }

}

