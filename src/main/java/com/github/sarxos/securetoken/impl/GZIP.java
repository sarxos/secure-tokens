package com.github.sarxos.securetoken.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;


/**
 * GZIP utility.
 * 
 * @author Bartosz Firyn (bfiryn)
 */
public class GZIP {

	/**
	 * Compress bytes with GZIP.
	 * 
	 * @param bytes the bytes to be compressed
	 * @return Array of compressed bytes
	 */
	public static final byte[] compress(byte[] bytes) {

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		GZIPOutputStream gos = null;

		try {
			gos = new GZIPOutputStream(baos);
			gos.write(bytes);
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			if (gos != null) {
				try {
					gos.close();
					baos.close();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}

		return baos.toByteArray();
	}

	/**
	 * Uncompress bytes with GZIP
	 * 
	 * @param bytes the bytes to be uncompressed
	 * @return Array of uncompressed bytes
	 */
	public static final byte[] uncompress(byte[] bytes) {

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
		GZIPInputStream gis = null;

		int n = 0;
		byte[] data = new byte[2048];

		try {
			gis = new GZIPInputStream(bais);
			while ((n = gis.read(data, 0, data.length)) != -1) {
				baos.write(data, 0, n);
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			if (gis != null) {
				try {
					gis.close();
					baos.close();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}

		return baos.toByteArray();
	}
}
