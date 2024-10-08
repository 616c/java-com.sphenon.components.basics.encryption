package com.sphenon.basics.encryption;

/****************************************************************************
  Copyright 2001-2024 Sphenon GmbH

  Licensed under the Apache License, Version 2.0 (the "License"); you may not
  use this file except in compliance with the License. You may obtain a copy
  of the License at http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
  License for the specific language governing permissions and limitations
  under the License.
*****************************************************************************/

import com.sphenon.basics.context.*;
import com.sphenon.basics.context.classes.*;
import com.sphenon.basics.exception.*;
import com.sphenon.basics.configuration.*;
import com.sphenon.basics.message.*;
import com.sphenon.basics.notification.*;
import com.sphenon.basics.customary.*;
import com.sphenon.basics.encoding.*;
import com.sphenon.basics.system.*;

import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.math.BigInteger;
import java.util.Map;
import java.util.HashMap;
import java.util.Base64;

// import java.io.IOException;
import java.io.UnsupportedEncodingException;
// import java.security.InvalidAlgorithmParameterException;
// import java.security.InvalidKeyException;
// import java.security.NoSuchAlgorithmException;
// import java.security.spec.AlgorithmParameterSpec;
// import java.security.spec.InvalidKeySpecException;
// import java.security.spec.KeySpec;
// import javax.crypto.spec.PBEKeySpec;
// import javax.crypto.spec.PBEParameterSpec;

public class EncryptionUtilities {
    static final public Class _class = EncryptionUtilities.class;

    static protected Configuration config;
    static { config = Configuration.create(RootContext.getInitialisationContext(), _class); };

    protected EncryptionUtilities(CallContext context) {
        Map<String,String> configured = config.get(context, "Initial", (Map<String,String>) null, ",", "=");
        if (configured != null) {
            for (String key : configured.keySet()) {
                setPassword(context, key, Encoding.recode(context, configured.get(key), Encoding.BASE64, Encoding.UTF8));
            }
        }
    }

    static protected volatile EncryptionUtilities singleton;

    static public EncryptionUtilities get(CallContext context) {
        if (singleton == null) {
            synchronized(EncryptionUtilities.class) {
                if (singleton == null) {
                    singleton = new EncryptionUtilities(context);
                }
            }
        }
        return singleton;
    }

    static final protected String UTF8 = "UTF-8";

    static final protected String algorithm = "Blowfish";
    // Blowfish               -  developed by Schneier
    // AES                    -  encouraged, recommended by NSA ;)
    // DES, PBEWithMD5AndDES  -  discourage, broken)
    //
    // https://stackoverflow.com/questions/5554526/comparison-of-des-triple-des-aes-blowfish-encryption-for-data
    // https://crypto.stackexchange.com/questions/24592/is-it-safe-to-use-pbewithmd5anddes
    //
    // For stronger encryption see file here STRONGER_ECRYPTION 

    protected Map<String,String> passwords_by_security_class;

    // obfuscation? - well, it protects deployables, not the server
    public void setPassword(CallContext context, String security_class, String password) {
        if (passwords_by_security_class == null) {
            passwords_by_security_class = new HashMap<String,String>();
        }
        passwords_by_security_class.put(security_class, password);
    }

    protected String getPassword(CallContext context, String security_class) {
        String password = null;
        if (passwords_by_security_class != null) {
            password = passwords_by_security_class.get(security_class);
        }
        if (password == null) {
            CustomaryContext.create((Context)context).throwConfigurationError(context, "Server not properly configured ('%(class)')", "class", security_class);
            throw (ExceptionConfigurationError) null; // compiler insists
        }
        return password;
    }

    public boolean isPasswordAvailable(CallContext context, String security_class) {
        return (passwords_by_security_class != null && passwords_by_security_class.get(security_class) != null ? true : false);
    }

    public String encryptForSecurityClass(CallContext context, String data, String security_class) {
        return encrypt(context, data, getPassword(context, security_class));
    }

    static public String encrypt(CallContext context, String data, String key) {
        try {
            return new String(Base64.getEncoder().encode(encrypt(context, data.getBytes(UTF8), key.getBytes(UTF8))));
        } catch(UnsupportedEncodingException uee) {
            CustomaryContext.create((Context)context).throwConfigurationError(context, uee, "Could not encrypt");
            throw (ExceptionConfigurationError) null; // compiler insists
        }
    }

    static public byte[] shorten(CallContext context, byte[] data, int target_length) {
        if (data.length <= target_length) { return data; }
        byte[] result = new byte[target_length];
        for (int i=0, j=0; i<data.length; i++, j++) {
            if (j == target_length) { j=0; }
            if (i < target_length) { result[j]  = data[i]; }
            else                   { result[j] ^= data[i]; }
        }
        return result;
    }

    static final protected int MAX_KEY_LENGTH = 56; // bytes

    static public byte[] encrypt(CallContext context, byte[] data, byte[] key) {
        try {
            SecretKey secret_key = new SecretKeySpec(shorten(context, key, MAX_KEY_LENGTH), algorithm);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secret_key);
            return cipher.doFinal(data);
        } catch(Exception e) {
            CustomaryContext.create((Context)context).throwConfigurationError(context, e, "Could not encrypt");
            throw (ExceptionConfigurationError) null; // compiler insists
        }
    }

    public String decryptForSecurityClass(CallContext context, String data, String security_class) {
        return decrypt(context, data, getPassword(context, security_class));
    }

    static public String decrypt(CallContext context, String data, String key) {
        try {
            return new String(decrypt(context, Base64.getDecoder().decode(data), key.getBytes(UTF8)), UTF8);
        } catch(UnsupportedEncodingException uee) {
            CustomaryContext.create((Context)context).throwConfigurationError(context, uee, "Could not encrypt");
            throw (ExceptionConfigurationError) null; // compiler insists
        }
    }

    static public byte[] decrypt(CallContext context, byte[] data, byte[] key) {
        try {
            SecretKey secret_key = new SecretKeySpec(shorten(context, key, MAX_KEY_LENGTH), algorithm);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, secret_key);
            return cipher.doFinal(data);
        } catch(Exception e) {
            CustomaryContext.create((Context)context).throwConfigurationError(context, e, "Could not decrypt");
            throw (ExceptionConfigurationError) null; // compiler insists
        }
    }

    static final protected int ITERATIONS = 65536; // maybe too slow...
    static final protected int KEY_LENGTH = 256; // bits

    // see WRONG_WAYS_TO_STORE_PASSWORD
    static public String hashPassword(CallContext context, String password, String salt){
        try {
            char[] passwordChars = password.toCharArray();
            byte[] saltBytes = salt.getBytes();

            PBEKeySpec spec = new PBEKeySpec(passwordChars, saltBytes, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
            return String.format("%x", new BigInteger(hashedPassword));
        } catch(Exception e) {
            CustomaryContext.create((Context)context).throwConfigurationError(context, e, "Could not hash");
            throw (ExceptionConfigurationError) null; // compiler insists
        }
    }

    // ------------------------------------------------------------------------------------------------------------------

    private static final char HEX_CHARS[] = new char[] {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

    static public String convertToHexString(CallContext context, byte[] bytes) {
        int i, n;
        int l = bytes.length;
        char[] chars = new char[l*2];
        for (i = l - 1; i >= 0; i--) {
            n = (int)bytes[i] & 0xFF;
            chars[i*2]   = HEX_CHARS[n/16];
            chars[i*2+1] = HEX_CHARS[n%16];
        }
        return new String(chars);
    }

    static public byte[] convertToBytes(CallContext context, String hex_string) {
        int l = hex_string.length();
        int size = l / 2;
        byte[] bytes = new byte[size];
        hex_string = hex_string.toUpperCase();
        for (int i=0, j=0; i < l; i+=2, j++) {
            char c1 = hex_string.charAt(i);
            char c2 = hex_string.charAt(i+1);
            char c = (char) ((c1 - (c1 > 64 ? 55 : 48)) * 16 + (c2 - (c2 > 64 ? 55 : 48)));
            bytes[j] = (byte) c;
        }
        return bytes;
    }

    public final static int DIGEST_ITERATIONS = 1000;
    public final static int SALT_SIZE         = 8; // bytes
    public final static int SECURITY_VERSION  = 2;

    static public byte[] createSalt(CallContext context) {
        return createSalt(context, SALT_SIZE);
    }

    static public byte[] createSalt(CallContext context, int salt_size) {
        SecureRandom random = null;
        String algorithm = "SHA1PRNG";
        try {
            random = SecureRandom.getInstance(algorithm);
        } catch (NoSuchAlgorithmException nsae) {
            CustomaryContext.create(Context.create(context)).throwConfigurationError(context, "SecureRandom algorithm '%(algorithm)' not available", "algorithm", algorithm);
            throw (ExceptionConfigurationError) null; // compiler insists
        }
        byte[] salt = new byte[salt_size];
        random.nextBytes(salt);
        return salt;
    }

    static public String getDigest(CallContext context, String password, String salt) {
        return getDigest(context, password, convertToBytes(context, salt));
    }

    static public String getDigest(CallContext context, String password, byte[] salt) {
        return getDigest(context, password, salt, 0, 0, 0);
    }

    // as used by UserBaseImpl.java
    // maybe to be aligned with (newer/better) hashPassword method above
    static public String getDigest(CallContext context, String password, byte[] salt, int salt_size, int iterations, int security_version) {
        if (salt_size        == 0) { salt_size        = SALT_SIZE; }
        if (iterations       == 0) { iterations       = DIGEST_ITERATIONS; }
        if (security_version == 0) { security_version = SECURITY_VERSION; }

        // see https://www.owasp.org/index.php/Hashing_Java
        // for recommendations on algorithm
        MessageDigest md;
        String algorithm = null;
        try {
            algorithm = (security_version >= 2 ? "SHA-512" : "SHA1");
            md = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException nsae) {
            CustomaryContext.create(Context.create(context)).throwConfigurationError(context, "MessageDigest algorithm '%(algorithm)' not available", "algorithm", algorithm);
            throw (ExceptionConfigurationError) null; // compiler insists
        }

        if (security_version >= 2) {
            md.reset();
            if (salt == null) {
                salt = SystemUtilities.getRandom(context, salt_size);
            }
            md.update(salt);
        }

        byte[] bytes = md.digest(password.getBytes());

        if (security_version >= 2) {
            for (int i = 0; i < iterations; i++) {
                md.reset();
                bytes = md.digest(bytes);
            }
        }

        String s1 = (security_version >= 2 ? EncryptionUtilities.convertToHexString(context, salt) : "");
        String s2 = EncryptionUtilities.convertToHexString(context, bytes);

        return s1 + s2;
   }

    static public String getHash(CallContext context, String text) {
        // see https://www.owasp.org/index.php/Hashing_Java
        // for recommendations on algorithm
        MessageDigest md;
        String algorithm = null;
        try {
            algorithm = "SHA-512";
            md = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException nsae) {
            CustomaryContext.create(Context.create(context)).throwConfigurationError(context, "MessageDigest algorithm '%(algorithm)' not available", "algorithm", algorithm);
            throw (ExceptionConfigurationError) null; // compiler insists
        }

        byte[] bytes = md.digest(text.getBytes());

        return EncryptionUtilities.convertToHexString(context, bytes);
   }
}
