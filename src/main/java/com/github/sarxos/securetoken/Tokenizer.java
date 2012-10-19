package com.github.sarxos.securetoken;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

import com.github.sarxos.securetoken.annotation.TokenEntity;
import com.github.sarxos.securetoken.annotation.TokenPart;
import com.github.sarxos.securetoken.impl.CipherEngine;
import com.github.sarxos.securetoken.impl.CipherType;
import com.github.sarxos.securetoken.impl.Converters;
import com.github.sarxos.securetoken.impl.GZIP;
import com.github.sarxos.securetoken.impl.Reflector;


public class Tokenizer {

	/**
	 * Token part to field mapping.
	 */
	private static final Map<Class<?>, Field[]> MAPPING = new HashMap<Class<?>, Field[]>();

	/**
	 * Empty immutable String array.
	 */
	private static final String[] EMPTY_STRING_ARRAY = new String[0];

	// /**
	// * Token delimiter.
	// */
	// private static final String DEFAULT_DELIMITER = "#";

	/**
	 * Compression markers.
	 */
	private static final byte[] CMP_MARKER = { 'c', 'm', 'p' };

	/**
	 * Decompression markers.
	 */
	private static final byte[] DCP_MARKER = { 'd', 'c', 'p' };

	/**
	 * Default cipher type.
	 */
	private static final CipherType DEFAULT_CIPHER = CipherType.AES;

	/**
	 * For given type returns only those fields which should become part of
	 * token data.
	 * 
	 * @param clazz the type which should be searched against token parts
	 * @return Array of fields which should be part of token
	 */
	private static Field[] getParts(Class<?> clazz) {

		Field[] parts = MAPPING.get(clazz);
		if (parts != null) {
			return parts;
		}

		Map<String, Field> convertable = new HashMap<String, Field>();
		Class<?> c = clazz;

		do {

			Field[] fields = c.getDeclaredFields();
			for (Field field : fields) {

				Class<?> type = field.getType();
				if (!Converters.canConvert(type)) {
					throw new IllegalArgumentException(String.format("Only basic type can be a token part, %s detected", type));
				}

				TokenPart tp = field.getAnnotation(TokenPart.class);
				if (tp != null) {

					String name = tp.value();
					if (convertable.get(name) != null) {
						throw new RuntimeException("Two or more fields cannot be annotated with the same token part name");
					}

					field.setAccessible(true);

					convertable.put(name, field);
				}
			}

		} while ((c = c.getSuperclass()) != null);

		parts = convertable.values().toArray(new Field[convertable.size()]);
		MAPPING.put(clazz, parts);

		return parts;
	}

	private static boolean startsWith(byte[] source, byte[] match) {
		if (match.length > source.length) {
			return false;
		}
		for (int i = 0; i < match.length; i++) {
			if (source[i] != match[i]) {
				return false;
			}
		}
		return true;
	}

	public static String tokenize(Token tokenizable, String password) {
		return tokenize(tokenizable, DEFAULT_CIPHER, password);
	}

	/**
	 * Tokenize object and then encrypt it.
	 * 
	 * @param tokenizable the object to be tokenized
	 * @param password the password to be used in encryption
	 * @param type the cipher type
	 * @return Encrypted string representation of given tokenizable object
	 */
	public static String tokenize(Token tokenizable, CipherType type, String password) {

		if (type == CipherType.NOOP) {
			return tokenize0(tokenizable);
		}

		byte[] decrypted = Strings.toUTF8ByteArray(tokenize0(tokenizable));
		byte[] compressed = GZIP.compress(decrypted);

		byte[] mark = DCP_MARKER;

		if (compressed.length < decrypted.length) {
			mark = CMP_MARKER;
			decrypted = compressed;
		}

		byte[] input = new byte[decrypted.length + mark.length];

		System.arraycopy(mark, 0, input, 0, mark.length);
		System.arraycopy(decrypted, 0, input, mark.length, decrypted.length);

		byte[] encrypted = CipherEngine.encrypt(type, password, input);

		return Strings.fromUTF8ByteArray(Base64.encode(encrypted));
	}

	private static TokenEntity getTokenEntity(Class<? extends Token> clazz) {
		Class<?> c = clazz;
		TokenEntity tf = null;
		do {
			tf = c.getAnnotation(TokenEntity.class);
			if (tf == null) {
				for (Class<?> i : c.getInterfaces()) {
					tf = i.getAnnotation(TokenEntity.class);
					if (tf != null) {
						return tf;
					}
				}
			} else {
				return tf;
			}
		} while ((c = clazz.getSuperclass()) != null);
		return null;
	}

	/**
	 * Tokenize object.
	 * 
	 * @param tokenizable the object to be tokenized
	 * @return String representation of tokenized data
	 */
	private static final String tokenize0(Token tokenizable) {

		Class<? extends Token> clazz = tokenizable.getClass();
		Constructor<? extends Token> ctor = Reflector.getConstructor(clazz);

		if (ctor == null) {
			throw new IllegalArgumentException(String.format("Default constructor missing in %s", clazz));
		}

		StringBuilder sb = new StringBuilder();

		String delimiter = null;
		String d = "";

		TokenEntity tf = getTokenEntity(clazz);
		delimiter = tf.delimiter();
		if (delimiter.length() == 0) {
			throw new IllegalArgumentException("Token delimiter cannot be empty");
		}

		Field[] parts = getParts(tokenizable.getClass());
		for (Field part : parts) {

			Object value = Reflector.getValue(part, tokenizable);
			TokenPart tp = part.getAnnotation(TokenPart.class);
			String string = Converters.toString(value);

			if (string.indexOf(delimiter) != -1) {
				throw new IllegalArgumentException(String.format("Cannot build token because part '%s' contains delimiter string '%s'", string, delimiter));
			}

			sb.append(d);
			sb.append(tp.value());
			sb.append('=');
			sb.append(string);

			d = delimiter;
		}

		return sb.toString();
	}

	public static <T extends Token> T objectify(Class<T> clazz, String token, String password) {
		return objectify(clazz, token, DEFAULT_CIPHER, password);
	}

	/**
	 * Objectify String first decrypting it.
	 * 
	 * @param <T> the type of class to be constructed
	 * @param clazz the class representing type to be constructed
	 * @param token the token to be decrypted and objectified
	 * @param type the cipher type to be used to decrypt
	 * @param password the password to be used as cipher secret
	 * @return Object of given type
	 */
	public static <T extends Token> T objectify(Class<T> clazz, String token, CipherType type, String password) {

		if (type == CipherType.NOOP) {
			return objectify0(clazz, token);
		}

		byte[] encrypted = Base64.decode(Strings.toUTF8ByteArray(token));
		byte[] decrypted = CipherEngine.decrypt(type, password, encrypted);

		byte[] output = null;

		if (startsWith(decrypted, CMP_MARKER)) {
			output = ArrayUtils.subarray(decrypted, CMP_MARKER.length, decrypted.length);
			output = GZIP.uncompress(output);
		} else {
			output = ArrayUtils.subarray(decrypted, DCP_MARKER.length, decrypted.length);
		}

		return objectify0(clazz, Strings.fromUTF8ByteArray(output));
	}

	/**
	 * Objectify string.
	 * 
	 * @param <T> the type to be created
	 * @param clazz the class representing type to be created
	 * @param token the token to be objectified
	 * @return Object of given type
	 */
	private static final <T extends Token> T objectify0(Class<T> clazz, String token) {

		T object = Reflector.newInstance(clazz);

		String delimiter = null;

		TokenEntity tf = getTokenEntity(clazz);
		delimiter = tf.delimiter();
		if (delimiter.length() == 0) {
			throw new IllegalArgumentException("Token delimiter cannot be empty");
		}

		int i = 0;

		Map<String, String> elements = new HashMap<String, String>();
		for (String string : split(token, delimiter)) {
			i = string.indexOf('=');
			elements.put(string.substring(0, i), string.substring(i + 1));
		}

		Field[] parts = getParts(clazz);
		for (Field part : parts) {

			TokenPart tp = part.getAnnotation(TokenPart.class);
			String key = tp.value();
			String string = elements.get(key);
			Object value = Converters.toObject(part.getType(), string);

			Reflector.setValue(part, object, value);
		}

		return object;
	}

	/**
	 * Performs the logic for the String split.
	 * 
	 * @param string the String to parse, may be null
	 * @param separator the separate character
	 * @return Array of Strings or null if null String input
	 */
	private static String[] split(String string, String separator) {

		if (string == null) {
			return null;
		}

		int len = string.length();
		if (len == 0) {
			return EMPTY_STRING_ARRAY;
		}

		List<String> list = new ArrayList<String>();

		int i = 0;
		int start = 0;

		boolean match = false;
		boolean last = false;

		if (separator == null) {

			// null separator means use whitespace

			while (i < len) {

				if (Character.isWhitespace(string.charAt(i))) {
					last = true;
					list.add(string.substring(start, i));
					match = false;
					start = ++i;
					continue;
				}

				last = false;
				match = true;
				i++;
			}
		} else if (separator.length() == 1) {

			// optimise 1 character case

			char sep = separator.charAt(0);

			while (i < len) {

				if (string.charAt(i) == sep) {
					last = true;
					list.add(string.substring(start, i));
					match = false;
					start = ++i;
					continue;
				}

				last = false;
				match = true;
				i++;
			}

		} else {

			// standard case

			while (i < len) {

				if (separator.indexOf(string.charAt(i)) >= 0) {
					last = true;
					list.add(string.substring(start, i));
					match = false;
					start = ++i;
					continue;
				}

				last = false;
				match = true;
				i++;
			}
		}

		if (match || last) {
			list.add(string.substring(start, i));
		}

		return list.toArray(new String[list.size()]);
	}

	/**
	 * Register converter to be used to translate strings to instances of
	 * specific class.
	 * 
	 * @param <C> the type of objects to be translated by given converter
	 * @param clazz the class representing type which will be converted
	 * @param converter the converter itself
	 */
	public static <C> void register(Class<C> clazz, Converter<C> converter) {
		Converters.register(clazz, converter);
	}

	/**
	 * Unregister converter bound with given class.
	 * 
	 * @param <C> the type of objects translated by converter
	 * @param clazz the class representing type being converted
	 */
	public static <C> void unregister(Class<C> clazz) {
		Converters.unregister(clazz);
	}

}
