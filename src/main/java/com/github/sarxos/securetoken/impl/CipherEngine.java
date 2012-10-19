package com.github.sarxos.securetoken.impl;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import com.github.sarxos.securetoken.CipherType;


public class CipherEngine {

	static {
		setup();
	}

	private static final Map<String, Cipher> CIPHERS = new HashMap<String, Cipher>();
	private static final Map<String, Key> KEYS = new HashMap<String, Key>();
	private static final Map<String, IvParameterSpec> IVS = new HashMap<String, IvParameterSpec>();

	private static final void setup() {
		if (Security.getProvider("BC") == null) {
			try {
				Security.addProvider(new BouncyCastleProvider());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private static final Cipher getCipher(CipherType type, String password) {

		String key = type.getAlgorithm() + ":" + password;

		Cipher cipher = CIPHERS.get(key);
		if (cipher != null) {
			return cipher;
		}

		String algorithm = type.getAlgorithm();
		try {
			cipher = Cipher.getInstance(algorithm, "BC");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException(e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException(e);
		}

		CIPHERS.put(key, cipher);

		return cipher;
	}

	private static final Key getKey(CipherType type, String password) {

		String kkey = type.getAlgorithm() + ":" + password;

		Key key = KEYS.get(kkey);
		if (key != null) {
			return key;
		}

		key = new SecretKeySpec(hmac(type, password), type.getAlgorithm());

		KEYS.put(kkey, key);

		return key;
	}

	private static final IvParameterSpec getIV(CipherType type, String password) {

		String key = type.getAlgorithm() + ":" + password;

		IvParameterSpec ivspec = IVS.get(key);
		if (ivspec != null) {
			return ivspec;
		}

		ivspec = new IvParameterSpec(hmac(type, password));

		IVS.put(key, ivspec);

		return ivspec;
	}

	/**
	 * Calculate RFC2104 HMAC of SHA1.
	 * 
	 * @param string the string to be used as input
	 * @return 8 bytes array
	 */
	private static final byte[] hmac(CipherType type, String string) {

		Digest digest = type.getDigest();

		byte[] hmac = new byte[digest.getDigestSize()];
		byte[] data = Strings.toUTF8ByteArray(string);

		HMac h = new HMac(digest);
		h.update(data, 0, data.length);
		h.doFinal(hmac, 0);

		return hmac;
	}

	/**
	 * Initialize cipher in specific mode.
	 * 
	 * @param cipher the cipher to be initialized
	 * @param mode the mode to put cipher in
	 * @param key the key to be used
	 * @param param the algorithm parameter to be used
	 */
	private static final void init(Cipher cipher, int mode, Key key, AlgorithmParameterSpec param) {
		try {
			cipher.init(mode, key, param);
		} catch (InvalidKeyException e) {
			throw new RuntimeException(String.format("Invalid key in %s", cipher.getAlgorithm()), e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Let cipher process data.
	 * 
	 * @param cipher the cipher to be used
	 * @param data the data to be processed
	 * @return Processed data
	 */
	private static final byte[] process(Cipher cipher, byte[] data) {
		try {
			return cipher.doFinal(data);
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException(e);
		} catch (BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Encrypt data.
	 * 
	 * @param type the cipher type to use
	 * @param decrypted the data to be encrypted
	 * @return Encrypted data
	 */
	public static final byte[] encrypt(CipherType type, String password, byte[] decrypted) {

		Cipher cipher = getCipher(type, password);
		Key key = getKey(type, password);
		IvParameterSpec iv = getIV(type, password);

		synchronized (cipher) {
			init(cipher, Cipher.ENCRYPT_MODE, key, iv);
			return process(cipher, decrypted);
		}
	}

	/**
	 * Decrypt data.
	 * 
	 * @param type the cipher type to be used
	 * @param encrypted the data to be decrypted
	 * @return Decrypted data
	 */
	public static final byte[] decrypt(CipherType type, String password, byte[] encrypted) {

		Cipher cipher = getCipher(type, password);
		Key key = getKey(type, password);
		IvParameterSpec iv = getIV(type, password);

		synchronized (cipher) {
			init(cipher, Cipher.DECRYPT_MODE, key, iv);
			return process(cipher, encrypted);
		}
	}

	public static void main(String[] args) {

		setup();

		byte[] bytes = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		byte[] encoded = encrypt(CipherType.BLOWFISH, "test1234", bytes);
		for (byte b : encoded) {
			System.out.print(b + " ");
		}
	}
}
