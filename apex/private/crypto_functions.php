<?php

// Symmetric Encryption

// Cipher method to use for symmetric encryption
const CIPHER_METHOD = 'AES-256-CBC';

function key_encrypt($string, $key, $cipher_method=CIPHER_METHOD) {
  // Needs a key of length 32 (256-bit)
  $key = str_pad($key, 32, '*');
  $iv_length = openssl_cipher_iv_length($cipher_method);
  $iv = openssl_random_pseudo_bytes($iv_length);

  // Encrypt
  $ciphertext = openssl_encrypt($string, $cipher_method, $key, OPENSSL_RAW_DATA, $iv);
  return base64_encode($iv . $ciphertext);
}

function key_decrypt($string, $key, $cipher_method=CIPHER_METHOD) {
  //Needs a key of length 32 (256-bit)
  $key = str_pad($key, 32, '*');

   // Base64 decode before decrypting
  $iv_with_ciphertext = base64_decode($string);

  // Separate initialization vector and encrypted string
  $iv_length = openssl_cipher_iv_length($cipher_method);
  $iv = substr($iv_with_ciphertext, 0, $iv_length);
  $ciphertext = substr($iv_with_ciphertext, $iv_length);

  // Decrypting
  $plaintext = openssl_decrypt($ciphertext, $cipher_method, $key, OPENSSL_RAW_DATA, $iv);
  return $plaintext;
}


// Asymmetric Encryption / Public-Key Cryptography

// Cipher configuration to use for asymmetric encryption
const PUBLIC_KEY_CONFIG = array(
    "digest_alg" => "sha512",
    "private_key_bits" => 2048,
    "private_key_type" => OPENSSL_KEYTYPE_RSA
); 

function generate_keys($config=PUBLIC_KEY_CONFIG) {
  $resource = openssl_pkey_new($config);

  openssl_pkey_export($resource, $private_key);

  $key_details = openssl_pkey_get_details($resource);
  $public_key = $key_details['key'];

  return array('private' => $private_key, 'public' => $public_key);
}

function pkey_encrypt($string, $public_key) {
  openssl_public_encrypt($string, $encrypted, $public_key);
  $message = base64_encode($encrypted);

  return $message;
}

function pkey_decrypt($string, $private_key) {
  // Decode from base64 to get raw data
  $ciphertext = base64_decode($string);
  openssl_private_decrypt($ciphertext, $decrypted, $private_key);

  return $decrypted;
}


// Digital signatures using public/private keys

function create_signature($data, $private_key) {
  $raw_signature = "";
	
  openssl_sign($data, $raw_signature, $private_key);
  
  // Use base64_encode to make contents viewable/sharable
  return base64_encode($raw_signature);
}

function verify_signature($data, $signature, $public_key) {
  $raw_signature = base64_decode($signature);

  // returns 1 if data and signature match 0 if not
  return openssl_verify($data, $raw_signature, $public_key);
}

?>
