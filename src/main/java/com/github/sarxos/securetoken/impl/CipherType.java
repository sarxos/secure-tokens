package com.github.sarxos.securetoken.impl;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.ShortenedDigest;


class Digests {

	public static final ExtendedDigest SHA1_20 = new SHA1Digest();
	public static final ExtendedDigest SHA1_16 = new ShortenedDigest(SHA1_20, 16);
	public static final ExtendedDigest SHA1_08 = new ShortenedDigest(SHA1_20, 8);
}

public enum CipherType {

	/**
	 * No-operation cipher - ignore encoding / decoding when used.
	 */
	NOOP("Noop", null),

	/**
	 * Data Encryption Standard (DES) cipher.
	 */
	DES("DES", Digests.SHA1_08),

	/**
	 * Advanced Encryption Standard (AES) is a specification for the encryption
	 * of electronic data established by the U.S. National Institute of
	 * Standards and Technology (NIST) in 2001.
	 */
	AES("AES", Digests.SHA1_16),

	/**
	 * SEED is a block cipher developed by the Korean Information Security
	 * Agency.
	 */
	SEED("SEED", Digests.SHA1_16),

	/**
	 * International Data Encryption Algorithm (IDEA) is a block cipher designed
	 * by James Massey of ETH Zurich and Xuejia Lai.
	 */
	IDEA("IDEA", Digests.SHA1_08),

	/**
	 * Noekeon (pronounced [nukion]) is a block cipher with a block length and a
	 * key length of 128 bits. It is a substitution-linear transformation
	 * network in bit-slice mode, and as such similar to AES proposal Serpent.
	 */
	NOEKEON("Noekeon", Digests.SHA1_16),

	/**
	 * Twofish is a symmetric key block cipher with a block size of 128 bits and
	 * key sizes up to 256 bits. It was one of the five finalists of the
	 * Advanced Encryption Standard contest, but was not selected for
	 * standardization.
	 */
	TWOFISH("Twofish", Digests.SHA1_16),

	/**
	 * Blowfish is a keyed, symmetric block cipher, designed in 1993 by Bruce
	 * Schneier and included in a large number of cipher suites and encryption
	 * products. Blowfish provides a good encryption rate in software and no
	 * effective cryptanalysis of it has been found to date.
	 */
	BLOWFISH("Blowfish", Digests.SHA1_08),

	/**
	 * Camellia is a 128-bit block cipher jointly developed by Mitsubishi and
	 * NTT. The cipher has been approved for use by the ISO/IEC, the European
	 * Union's NESSIE project and the Japanese CRYPTREC project.
	 */
	CAMELIA("Camellia", Digests.SHA1_16),

	/**
	 * Serpent is a symmetric key block cipher which was a finalist in the
	 * Advanced Encryption Standard (AES) contest, where it came second to
	 * Rijndael. Serpent was designed by Ross Anderson, Eli Biham, and Lars
	 * Knudsen.
	 */
	SERPENT("Serpent", Digests.SHA1_16);

	/**
	 * The algorithm name.
	 */
	private String algorithm = null;

	/**
	 * Digest.
	 */
	private Digest digest = null;

	private CipherType(String name, Digest digest) {
		this.algorithm = name;
		this.digest = digest;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public Digest getDigest() {
		return digest;
	}
}
