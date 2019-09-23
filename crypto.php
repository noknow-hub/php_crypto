<?php
//////////////////////////////////////////////////////////////////////
// crypto.php
//
// @usage
//
//     1. Load this file.
//
//         --------------------------------------------------
//         require_once('crypto.php');
//         use noknow\lib\crypto\crypto;
//         --------------------------------------------------
//
//     2. Initialize Crypto class.
//
//         --------------------------------------------------
//         $crypto = new crypto\Crypto();
//         --------------------------------------------------
//
//     3. Now, you can use it!!
//
//         --------------------------------------------------
//         $plainText = 'Hello World';
//         $key = 'abcdefghijklmnopqrstuvwxyz123456';
//         --------------------------------------------------
//
//         3-1. When using CBC mode.
//
//             --------------------------------------------------
//             // Encryption in the first block.
//             $cipherText = $crypto->EncryptCBC($plainText, $key);
//             
//             // Encryption after the second block.
//             $cipherText = $crypto->EncryptCBC($plainText, $key, $cipherText);
//             
//             // Decryption
//             $plainText = $crypto->DecryptCBC($cipherText, $key);
//             
//             // Verification
//             $crypto->VerifyCBC($plainText, $cipherText, $key)
//             --------------------------------------------------
//
//         3-2. When using CTR mode.
//
//             --------------------------------------------------
//             // Encryption in the first block.
//             $cipherText = $crypto->EncryptCTR($plainText, $key);
//             
//             // Encryption after the second block.
//             $cipherText = $crypto->EncryptCTR($plainText, $key, $cipherText);
//             
//             // Decryption
//             $plainText = $crypto->DecryptCTR($cipherText, $key);
//             
//             // Verification
//             $crypto->VerifyCTR($plainText, $cipherText, $key)
//             --------------------------------------------------
//
//         3-3. When using a token with time limit.
//
//             --------------------------------------------------
//             // time limit is 5 minutes from now.
//             $limit = 60 * 5;  // 300 seconds.
//
//             // Encryption with CBC mode.
//             $cipherText = $crypto->GenTokenCBC($plainText, $limit, $key);
//
//             // Verify with CBC mode.
//             $ok = $crypto->VerifyTokenCBC($plainText, $cipherText, $key);
//  
//             // Encryption with CTR mode.
//             $cipherText = $crypto->GenTokenCTR($plainText, $limit, $key);
//  
//             // Verify with CTR mode.
//             $ok = $crypto->VerifyTokenCTR($plainText, $cipherText, $key);
//             --------------------------------------------------
//
//
// MIT License
//
// Copyright (c) 2019 noknow.info
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTW//ARE.
//////////////////////////////////////////////////////////////////////

namespace noknow\lib\crypto\crypto;

use DateTime;

class Crypto {

    //////////////////////////////////////////////////////////////////////
    // Properties
    //////////////////////////////////////////////////////////////////////
    const METHOD_CBC = 'aes-256-cbc';
    const METHOD_CTR = 'aes-256-ctr';
    private $version;


    //////////////////////////////////////////////////////////////////////
    // Constructor
    //////////////////////////////////////////////////////////////////////
    public function __construct() {
        $this->version = phpversion();
    }


    //////////////////////////////////////////////////////////////////////
    // Encrypt by CBC mode.
    //////////////////////////////////////////////////////////////////////
    public function EncryptCBC(string $plainText, string $key, string $iv = NULL): ?string {
        if(is_null($iv)) {
            $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(self::METHOD_CBC));
        }
        $encrypted = openssl_encrypt($plainText, self::METHOD_CBC, $key, OPENSSL_RAW_DATA, $iv);
        if($encrypted === FALSE) {
            return NULL;
        }
        $cipherText = bin2hex($encrypted . ':::' . $iv);
        return $cipherText;
    }


    //////////////////////////////////////////////////////////////////////
    // Decrypt by CBC mode.
    //////////////////////////////////////////////////////////////////////
    public function DecryptCBC(string $cipherText, string $key): ?string {
        $rawData = hex2bin($cipherText);
        if($rawData === FALSE) {
            return NULL;
        }
        $rawData = explode(':::', $rawData);
        if(count($rawData) !== 2) {
            return NULL;
        }
        $encrypted = $rawData[0];
        $iv = $rawData[1];
        $plainText = openssl_decrypt($encrypted, self::METHOD_CBC, $key, OPENSSL_RAW_DATA, $iv);
        if($plainText === FALSE) {
            return NULL;
        }
        return $plainText;
    }


    //////////////////////////////////////////////////////////////////////
    // Verify by CBC mode.
    //////////////////////////////////////////////////////////////////////
    public function VerifyCBC(string $plainText, string $cipherText, string $key): bool {
        $decrypted = $this->DecryptCBC($cipherText, $key);
        if(is_null($decrypted)) {
            return FALSE;
        }
        if($plainText === $decrypted) {
            return TRUE;
        } else {
            return FALSE;
        }
    }


    //////////////////////////////////////////////////////////////////////
    // Encrypt by CTR mode.
    //////////////////////////////////////////////////////////////////////
    public function EncryptCTR(string $plainText, string $key, string $nonce = NULL): ?string {
        if(is_null($nonce)) {
            $nonce = openssl_random_pseudo_bytes(openssl_cipher_iv_length(self::METHOD_CTR));
        }
        $encrypted = openssl_encrypt($plainText, self::METHOD_CTR, $key, OPENSSL_RAW_DATA, $nonce);
        if($encrypted === FALSE) {
            return NULL;
        }
        $cipherText = bin2hex($encrypted . ':::' . $nonce);
        return $cipherText;
    }


    //////////////////////////////////////////////////////////////////////
    // Decrypt by CTR mode.
    //////////////////////////////////////////////////////////////////////
    public function DecryptCTR(string $cipherText, string $key): ?string {
        $rawData = hex2bin($cipherText);
        if($rawData === FALSE) {
            return NULL;
        }
        $rawData = explode(':::', $rawData);
        if(count($rawData) !== 2) {
            return NULL;
        }
        $encrypted = $rawData[0];
        $nonce = $rawData[1];
        $plainText = openssl_decrypt($encrypted, self::METHOD_CTR, $key, OPENSSL_RAW_DATA, $nonce);
        if($plainText === FALSE) {
            return NULL;
        }
        return $plainText;
    }


    //////////////////////////////////////////////////////////////////////
    // Verify by CTR mode.
    //////////////////////////////////////////////////////////////////////
    public function VerifyCTR(string $plainText, string $cipherText, string $key): bool {
        $decrypted = $this->DecryptCTR($cipherText, $key);
        if(is_null($decrypted)) {
            return FALSE;
        }
        if($plainText === $decrypted) {
            return TRUE;
        } else {
            return FALSE;
        }
    }


    //////////////////////////////////////////////////
    // Generate a token with time limit using CBC mode.
    //////////////////////////////////////////////////
    public function GenTokenCBC(string $plainText, int $secondLimit, string $key, string $iv = NULL): ?string {
        $expires = new DateTime();
        $expires->modify('+' . $secondLimit . ' seconds');
        $token = array(
            'data' => $plainText,
            'expires' => $expires->getTimestamp(),
        );
        $jsonStr = json_encode($token);
        if($jsonStr === FALSE) {
            return NULL;
        }
        return $this->EncryptCBC($jsonStr, $key, $iv);
    }


    //////////////////////////////////////////////////
    // Verify a token with time limit using CBC mode.
    //////////////////////////////////////////////////
    public function VerifyTokenCBC(string $plainText, string $cipherText, string $key): bool {
        $decrypted = $this->DecryptCBC($cipherText, $key);
        if(is_null($decrypted)) {
            return FALSE;
        }
        $json = json_decode($decrypted, TRUE);
        if(is_null($json)) {
            return FALSE;
        }
        if($plainText !== $json['data']) {
            return FALSE;
        }
        $now = new DateTime();
        return $json['expires'] > $now->getTimestamp();
    }


    //////////////////////////////////////////////////
    // Generate a token with time limit using CTR mode.
    //////////////////////////////////////////////////
    public function GenTokenCTR(string $plainText, int $secondLimit, string $key, string $nonce = NULL): ?string {
        $expires = new DateTime();
        $expires->modify('+' . $secondLimit . ' seconds');
        $token = array(
            'data' => $plainText,
            'expires' => $expires->getTimestamp(),
        );
        $jsonStr = json_encode($token);
        if($jsonStr === FALSE) {
            return NULL;
        }
        return $this->EncryptCTR($jsonStr, $key, $nonce);
    }


    //////////////////////////////////////////////////
    // Verify a token with time limit using CTR mode.
    //////////////////////////////////////////////////
    public function VerifyTokenCTR(string $plainText, string $cipherText, string $key): bool {
        $decrypted = $this->DecryptCTR($cipherText, $key);
        if(is_null($decrypted)) {
            return FALSE;
        }
        $json = json_decode($decrypted, TRUE);
        if(is_null($json)) {
            return FALSE;
        }
        if($plainText !== $json['data']) {
            return FALSE;
        }
        $now = new DateTime();
        return $json['expires'] > $now->getTimestamp();
    }

}
