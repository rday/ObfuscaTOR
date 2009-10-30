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
class WaveCaptcha implements ICaptcha {

   function WaveCaptcha() { $this->c = new easy_captcha(); }
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

      #-- create new
//      if (empty($this->id) || !$ignore_expiration && !$this->is_valid() && $this->log("new()", "EXPIRED", "regenerating store")) {
         $this->generate();
  //    }
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
      $this->image = new easy_captcha_graphic_image_waved();
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

#-- waived captcha image II
class easy_captcha_graphic_image_waved extends easy_captcha_graphic {


   /* returns jpeg file stream with unscannable letters encoded 
      in front of colorful disturbing background
   */
   function jpeg() {
      #-- step by step
      $this->create();
      $this->text();
      //$this->debug_grid();
      $this->fog();
      $this->distort();
      return $this->output();
   }


   #-- initialize in-memory image with gd library
   function create() {
      $this->img = imagecreatetruecolor($this->width, $this->height);
     // imagealphablending($this->img, TRUE);
      imagefilledrectangle($this->img, 0,0, $this->width,$this->height, $this->inverse ? $this->bg ^ 0xFFFFFF : $this->bg); //$this->rgb(255,255,255)
      if (function_exists("imageantialias")) {
         imageantialias($this->img, true);
      }
   }


   #-- add the real text to it
   function text() {
      $w = $this->width;
      $h = $this->height;
      $SIZE = rand(15,20);
      $DEG = rand(-2,2);
      $LEN = strlen($this->solution);
      $left = $w - $LEN;// * 25;
      $top = ($h - $SIZE - abs($DEG*2));
      //imagettftext($this->img, $SIZE, $DEG, rand(5,$left-5), $h-rand(3, $top-3), $this->rgb(0,0,0), $this->font(), $this->solution);
      $lines = explode("\n", $this->solution);
      $yPos = 0;
      foreach($lines as $line) {
	  $yPos += $SIZE;
          imagettftext($this->img, $SIZE, $DEG, rand(12,24), $yPos + rand(9, 16), $this->rgb(0,0,0), $this->font(), $line);
	}
   }
   function debug_grid() {
      for ($x=0; $x<250; $x+=10) {
         imageline($this->img, $x, 0, $x, 70, 0x333333);
         imageline($this->img, 0, $x, 250, $x, 0x333333);
      }
   }

   #-- add lines
   function fog() {
      $num = rand(10,25);
      $x = $this->width;
      $y = $this->height;
      $s = rand(0,270);
      for ($n=0; $n<$num; $n++) {
         imagesetthickness($this->img, rand(1,2));
         imagearc($this->img,
            rand(0.1*$x, 0.9*$x), rand(0.1*$y, 0.9*$y),  //x,y
            rand(0.1*$x, 0.3*$x), rand(0.1*$y, 0.3*$y),  //w,h
            $s, rand($s+5, $s+90),     // s,e
            rand(0,1) ? 0xFFFFFF : 0x000000   // col
         );
      }
      imagesetthickness($this->img, 1);
   }


   #-- distortion: wave-transform
   function distort() {

      #-- init
      $single_pixel = (CAPTCHA_PIXEL<=1);   // very fast
      $greyscale2x2 = (CAPTCHA_PIXEL<=2);   // quicker than exact smooth 2x2 copy
      $width = $this->width;
      $height = $this->height;
      $i = & $this->img;
      $dest = imagecreatetruecolor($width, $height);

      #-- URL param ?hires=1 influences used drawing scheme
      if (isset($_GET["hires"])) {
         $single_pixel = 0;
      }
      #-- prepare distortion
      $wave = new easy_captcha_dxy_wave($width, $height);
      $spike = new easy_captcha_dxy_spike($width, $height);

      #-- generate each new x,y pixel individually from orig $img
      for ($y = 0; $y < $height; $y++) {
         for ($x = 0; $x < $width; $x++) {

            #-- pixel movement
            list($dx, $dy) = $wave->dxy($x, $y);   // x- and y- sinus wave
           // list($qx, $qy) = $spike->dxy($x, $y);

            #-- get source pixel, paint dest
            if ($single_pixel) {
               // single source dot: one-to-one duplicate (unsmooth, hard edges)
               imagesetpixel($dest, $x, $y, @imagecolorat($i, (int)$dx+$x, (int)$dy+$y));
            }
            elseif ($greyscale2x2) {
               // merge 2x2 simple/greyscale (3 times as slow)
               $cXY = $this->get_2x2_greyscale($i, $x+$dx, $y+$dy);
               imagesetpixel($dest, $x,$y, imagecolorallocate($dest, $cXY, $cXY, $cXY));
            }
            else {
               // exact and smooth transformation (5 times as slow)
               list($cXY_R, $cXY_G, $cXY_B) = $this->get_2x2_smooth($i, $x+$dx, $y+$dy);
               imagesetpixel($dest, $x,$y, imagecolorallocate($dest, (int)$cXY_R, (int)$cXY_G, (int)$cXY_B));
            }

         }
      }

      #-- simply overwrite ->img
      imagedestroy($i);
      $this->img = $dest;
   }

   #-- get 4 pixels from source image, merges BLUE value simply
   function get_2x2_greyscale(&$i, $x, $y) {
       // this is pretty simplistic method, actually adds more artefacts
       // than it "smoothes"
       // it just merges the brightness from 4 adjoining pixels into one
       $cXY = (@imagecolorat($i, $x+$dx, $y+$dy) & 0xFF)
            + (@imagecolorat($i, $x+$dx, $y+$dy+1) & 0xFF)
            + (@imagecolorat($i, $x+$dx+1, $y+$dy) & 0xFF)
            + (@imagecolorat($i, $x+$dx+1, $y+$dy+1) & 0xFF);
       $cXY = (int) ($cXY / 4);
       return $cXY;
   }

   #-- smooth pixel reading (with x,y being reals, not integers)
   function get_2x2_smooth(&$i, $x, $y) {
       // get R,G,B values from 2x2 source area
       $c00 = $this->get_RGB($i, $x, $y);      //  +------+------+
       $c01 = $this->get_RGB($i, $x, $y+1);    //  |dx,dy | x1,y0|
       $c10 = $this->get_RGB($i, $x+1, $y);    //  | rx-> |      | 
       $c11 = $this->get_RGB($i, $x+1, $y+1);  //  +----##+------+
       // weighting by $dx/$dy fraction part   //  |    ##|<-ry  |
       $rx = $x - floor($x);  $rx_ = 1 - $rx;  //  |x0,y1 | x1,y1|
       $ry = $y - floor($y);  $ry_ = 1 - $ry;  //  +------+------+
       // this is extremely slow, but necessary for correct color merging,
       // the source pixel lies somewhere in the 2x2 quadrant, that's why
       // RGB values are added proportionately (rx/ry/_)
       // we use no for-loop because that would slow it even further
       $cXY_R = (int) (($c00[0]) * $rx_ * $ry_)
              + (int) (($c01[0]) * $rx_ * $ry)      // division by 4 not necessary,
              + (int) (($c10[0]) * $rx * $ry_)      // because rx/ry/rx_/ry_ add up
              + (int) (($c11[0]) * $rx * $ry);      // to 255 (=1.0) at most
       $cXY_G = (int) (($c00[1]) * $rx_ * $ry_)
              + (int) (($c01[1]) * $rx_ * $ry)
              + (int) (($c10[1]) * $rx * $ry_)
              + (int) (($c11[1]) * $rx * $ry);
       $cXY_B = (int) (($c00[2]) * $rx_ * $ry_)
              + (int) (($c01[2]) * $rx_ * $ry)
              + (int) (($c10[2]) * $rx * $ry_)
              + (int) (($c11[2]) * $rx * $ry);
       return array($cXY_R, $cXY_G, $cXY_B);
   }
   #-- imagegetcolor from current ->$img split up into RGB array
   function get_RGB(&$img, $x, $y) {
      $rgb = @imagecolorat($img, $x, $y);
      return array(($rgb >> 16) &0xFF, ($rgb >>8) &0xFF, ($rgb) &0xFF);
   }
}






#-- xy-wave deviation (works best for around 200x60)
#   cos(x,y)-idea taken from imagemagick
class easy_captcha_dxy_wave {

   #-- init params
   function easy_captcha_dxy_wave($max_x, $max_y) {
      $this->dist_x = $this->real_rand(2.5, 4.5);     // max +-x/y delta distance
      $this->dist_y = $this->real_rand(2.5, 4.5);
      //$this->slow_x = $this->real_rand(7.5, 20.0);    // =wave-width in pixel/3
      $this->slow_x = $this->real_rand(10.5, 25.0);    // =wave-width in pixel/3
      //$this->slow_y = $this->real_rand(7.5, 15.0);
      $this->slow_y = $this->real_rand(10.5, 17.0);
   }

   #-- calculate source pixel position with overlapping sinus x/y-displacement
   function dxy($x, $y) {
      #-- adapting params
      $this->dist_x *= 1.000035;
      $this->dist_y *= 1.000015;
      #-- dest pixels (with x+y together in each of the sin() calcs you get more deformation, else just yields y-ripple effect)
      $dx = $this->dist_x * cos(($x/$this->slow_x) - ($y/1.1/$this->slow_y));
      $dy = $this->dist_y * sin(($y/$this->slow_y) - ($x/0.9/$this->slow_x));
      #-- result
      return array($dx, $dy);
   }

   #-- array of values with random start/end values
   function from_to_rand($max, $a, $b) {
      $BEG = $this->real_rand($a, $b);
      $DIFF = $this->real_rand($a, $b) - $BEG;
      $r = array();
      for ($i = 0; $i <= $max; $i++) {
         $r[$i] = $BEG + $DIFF * $i / $max;
      }
      return($r);
   }

   #-- returns random value in given interval
   function real_rand($a, $b) {
      $r = rand(0, 1<<30);
      return(  $r / (1<<30) * ($b-$a) + $a  );   // base + diff * (0..1)
   }
}


#-- with spike
class easy_captcha_dxy_spike {
   function dxy($x,$y) {
      #-- centre spike
      $y += 0.0;
      return array($x,$y);
   }
}

