<?php
/**
 */

interface ICaptcha {
   /* This method should do whatever is neccesary to create a JPEG and
      should return the image as a string */
   public function CreateJPEG();

   /* This method was going to be used to save to a file, but given all the
      unknowns in whatever URLs, globals, temp directories, etc, in the
      user environment, I think its probably better to have the user handle
      the output of CreateJPEG() manually */
   public function Save();

   /* Set the image height */
   public function SetHeight($height);

   /* Set the image width */
   public function SetWidth($width);

   /* Set the image text */
   public function SetText($text);
}
