<?php
/**
 * ZLX Security
 *
 * @author		Alexandre de Freitas Caetano <https://github.com/aledefreitas>
 */
namespace ZLX\Security;

/**
 * Classe para lidar com criptografia
 */
class Security
{
    /**
     * SALT used in this instance
     *
     * @var string
     */
    private $_salt = "";

    /**
     * Constructor method
     *
     * @param   string      $salt       SALT used for encrypting
     *
     * @return void
     */
    public function __construct($salt)
    {
        $this->_salt = $salt;
    }

    /**
     * Generates an encryption private key
     *
     * @param   string      $cipher_key         Public key
     *
     * @return string
     */
    private function _genKey($cipher_key)
    {
        return mb_substr(hash('sha256', $cipher_key . $this->_salt), 0, 32, '8bit');
    }

    /**
     * Generates the HMAC for the ciphered string
     *
     * @param   string      $cipher_string      Ciphered string
     * @param   string      $cipher_key         Private key
     *
     * @return string
     */
    private function _genHmac($cipher_string, $cipher_key)
    {
        return hash_hmac('sha256', $cipher_string, $cipher_key);
    }

    /**
     * Validates if the provided hmac is equal to the expected hmac
     *
     * @param   string      $hmac           Provided hmac
     * @param   string      $compareHmac    Expected hmac
     *
     * @return boolean
     */
    private function validHmac($hmac, $compareHmac)
    {
        if(function_exists("hash_equals")) {
            return hash_equals($hmac, $compareHmac);
        }

        $hashLength = mb_strlen($hmac, '8bit');
        $compareLength = mb_strlen($compareHmac, '8bit');

        if ($hashLength !== $compareLength) {
            return false;
        }

        $result = 0;

        for ($i = 0; $i < $hashLength; $i++) {
            $result |= (ord($hmac[$i]) ^ ord($compareHmac[$i]));
        }

        return $result === 0;
    }

    /**
     * Hashes a string
     *
     * @param   string      $string     String to hash
     *
     * @return string
     */
    public function hash($string)
    {
        return hash('sha256', $string);
    }

    /**
     * Encrypts a string using a secret
     *
     * @param   string      $original_string        Original string
     * @param   string      $cipher_key             Secret used to encrypt
     *
     * @return string
     */
    public function encrypt($original_string, $cipher_key)
    {
        $cipher_key = $this->_genKey($cipher_key);

        $ivSize = openssl_cipher_iv_length('AES-256-CBC');
        $iv = openssl_random_pseudo_bytes($ivSize);

        $cipher_text = $iv . openssl_encrypt($original_string, 'AES-256-CBC', $cipher_key, OPENSSL_RAW_DATA, $iv);

        return $this->_genHmac($cipher_text, $cipher_key) . $cipher_text;
    }

    /**
     * Decrypts a string using a secret
     *
     * @param   string      $cipher_string          Ciphered string
     * @param   string      $cipher_key             Secret used to encrypt
     *
     * @return string
     */
    public function decrypt($cipher_string, $cipher_key)
    {
        $cipher_key = $this->_genKey($cipher_key);

        $hmacSize = 64;
        $hmacString = mb_substr($cipher_string, 0, $hmacSize, "8bit");
        $cipher_text = mb_substr($cipher_string, $hmacSize, null, "8bit");

        if(!$this->validHmac($hmacString, $this->_genHmac($cipher_text, $cipher_key)))
            return false;

        $ivSize = openssl_cipher_iv_length('AES-256-CBC');
        $iv = mb_substr($cipher_text, 0, $ivSize, '8bit');
        $cipher_text = mb_substr($cipher_text, $ivSize, null, '8bit');

        return openssl_decrypt($cipher_text, 'AES-256-CBC', $cipher_key, OPENSSL_RAW_DATA, $iv);
    }
}
