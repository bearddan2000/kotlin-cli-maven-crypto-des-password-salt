package example;

import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.apache.commons.codec.binary.Base64;

class Main {
  lateinit var encryptCipher: Cipher;
  lateinit var decryptCipher: Cipher;

/**
 * Construct a new object which can be utilized to encrypt
 * and decrypt strings using the specified key
 * with a DES encryption algorithm.
 *
 * @param key The secret key used in the crypto operations.
 * @throws Exception If an error occurs.
 *
 */
@Throws(Exception::class)
fun genSecret(key: SecretKey) {
    encryptCipher = Cipher.getInstance("DES");
    decryptCipher = Cipher.getInstance("DES");
    encryptCipher.init(Cipher.ENCRYPT_MODE, key);
    decryptCipher.init(Cipher.DECRYPT_MODE, key);
}

/**
 * Encrypt a string using DES encryption, and return the encrypted
 * string as a base64 encoded string.
 * @param unencryptedString The string to encrypt.
 * @return String The DES encrypted and base 64 encoded string.
 * @throws Exception If an error occurs.
 */
@Throws(Exception::class)
fun encryptBase64 (unencryptedString: String): String {
    // Encode the string into bytes using utf-8
    val unencryptedByteArray: ByteArray = unencryptedString.toByteArray();

    // Encrypt
    val encryptedBytes: ByteArray = encryptCipher.doFinal(unencryptedByteArray);

    // Encode bytes to base64 to get a string
    val encodedBytes: ByteArray = Base64.encodeBase64(encryptedBytes);

    return String(encodedBytes);
}

/**
 * Decrypt a base64 encoded, DES encrypted string and return
 * the unencrypted string.
 * @param encryptedString The base64 encoded string to decrypt.
 * @return String The decrypted string.
 * @throws Exception If an error occurs.
 */
@Throws(Exception::class)
fun decryptBase64 (encryptedString: String): String {
    // Encode bytes to base64 to get a string
    val decodedBytes: ByteArray = Base64.decodeBase64(encryptedString.toByteArray());

    // Decrypt
    val unencryptedByteArray: ByteArray = decryptCipher.doFinal(decodedBytes);

    // Decode using utf-8
    return String(unencryptedByteArray);
  }
}

/**
 * Main unit test method.
 * @param args Command line arguments.
 *
 */
fun main(args: Array<String>) {
    try {
        //Generate the secret key
        val m: Main = Main()
        val password = "abcd1234";
        val key = DESKeySpec(password.toByteArray());
        val keyFactory = SecretKeyFactory.getInstance("DES");
        val secretKey = keyFactory.generateSecret(key);
        val salt = java.util.Base64.getEncoder().encodeToString(secretKey.getEncoded());

        //Instantiate the encrypter/decrypter
        m.genSecret(secretKey);
        val plaintext = "Hello World";
        val encryptedString = m.encryptBase64(plaintext);
        // Encrypted String:8dKft9vkZ4I=
        println("Salt: "+salt);
        println("Encrypted String: "+encryptedString);

        //Decrypt the string
        val unencryptedString = m.decryptBase64(encryptedString);
        // UnEncrypted String:Message
        println("UnEncrypted String:"+unencryptedString);

    } catch( e: Exception ){
        println("Error:"+e.toString());
    }
  }
