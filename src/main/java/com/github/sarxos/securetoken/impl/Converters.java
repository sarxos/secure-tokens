package com.github.sarxos.securetoken.impl;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import com.github.sarxos.securetoken.Converter;


public class Converters {

	private static final class StringConverter implements Converter<String> {

		@Override
		public String toObject(String string) {
			return string;
		}

		@Override
		public String toString(String object) {
			return object;
		}
	}

	private static final class BooleanConverter implements Converter<Boolean> {

		@Override
		public Boolean toObject(String string) {
			return Boolean.parseBoolean(string);
		}

		@Override
		public String toString(Boolean object) {
			return Boolean.toString(object);
		}
	}

	private static final class CharacterConverter implements Converter<Character> {

		@Override
		public Character toObject(String string) {
			return Character.valueOf(string.charAt(0));
		}

		@Override
		public String toString(Character object) {
			return Character.toString(object);
		}
	}

	private static final class ByteConverter implements Converter<Byte> {

		@Override
		public Byte toObject(String string) {
			return Byte.parseByte(string);
		}

		@Override
		public String toString(Byte object) {
			return Byte.toString(object);
		}
	}

	private static final class ShortConverter implements Converter<Short> {

		@Override
		public Short toObject(String string) {
			return Short.parseShort(string);
		}

		@Override
		public String toString(Short object) {
			return Short.toString(object);
		}
	}

	private static final class IntegerConverter implements Converter<Integer> {

		@Override
		public Integer toObject(String string) {
			return Integer.parseInt(string);
		}

		@Override
		public String toString(Integer object) {
			return Integer.toString(object);
		}
	}

	private static final class LongConverter implements Converter<Long> {

		@Override
		public Long toObject(String string) {
			return Long.parseLong(string);
		}

		@Override
		public String toString(Long object) {
			return Long.toString(object);
		}
	}

	private static final class FloatConverter implements Converter<Float> {

		@Override
		public Float toObject(String string) {
			return Float.parseFloat(string);
		}

		@Override
		public String toString(Float object) {
			return Float.toString(object);
		}
	}

	private static final class DoubleConverter implements Converter<Double> {

		@Override
		public Double toObject(String string) {
			return Double.parseDouble(string);
		}

		@Override
		public String toString(Double object) {
			return Double.toString(object);
		}
	}

	private static final class VoidConverter implements Converter<Void> {

		@Override
		public Void toObject(String string) {
			return null;
		}

		@Override
		public String toString(Void object) {
			return "";
		}
	}

	private static final class BigDecimalConverter implements Converter<BigDecimal> {

		@Override
		public BigDecimal toObject(String string) {
			return new BigDecimal(string);
		}

		@Override
		public String toString(BigDecimal object) {
			return object.toEngineeringString();
		}
	}

	private static final class BigIntegerConverter implements Converter<BigInteger> {

		@Override
		public BigInteger toObject(String string) {
			return new BigInteger(string);
		}

		@Override
		public String toString(BigInteger object) {
			return object.toString();
		}
	}

	/**
	 * Mapping from primitive to boxing type.
	 */
	private static final Map<Class<?>, Class<?>> PRIMITIVES_MAPPING = new HashMap<Class<?>, Class<?>>();

	/**
	 * Converters mapping.
	 */
	private static final Map<Class<?>, Converter<?>> CONVERTERS = new HashMap<Class<?>, Converter<?>>();

	/**
	 * Is reactor initialized.
	 */
	private static boolean initialized = false;

	/**
	 * Initialize converters.
	 */
	private static void init() {

		if (initialized) {
			return;
		}

		PRIMITIVES_MAPPING.put(boolean.class, Boolean.class);
		PRIMITIVES_MAPPING.put(char.class, Character.class);
		PRIMITIVES_MAPPING.put(byte.class, Byte.class);
		PRIMITIVES_MAPPING.put(short.class, Short.class);
		PRIMITIVES_MAPPING.put(int.class, Integer.class);
		PRIMITIVES_MAPPING.put(long.class, Long.class);
		PRIMITIVES_MAPPING.put(float.class, Float.class);
		PRIMITIVES_MAPPING.put(double.class, Double.class);

		register(String.class, new StringConverter());
		register(boolean.class, new BooleanConverter());
		register(char.class, new CharacterConverter());
		register(byte.class, new ByteConverter());
		register(short.class, new ShortConverter());
		register(int.class, new IntegerConverter());
		register(long.class, new LongConverter());
		register(float.class, new FloatConverter());
		register(double.class, new DoubleConverter());
		register(Void.class, new VoidConverter());
		register(BigDecimal.class, new BigDecimalConverter());
		register(BigInteger.class, new BigIntegerConverter());

		initialized = true;
	}

	/**
	 * Register converter for the specific class.
	 * 
	 * @param <C> the generic type to be registered
	 * @param clazz the class representing given type
	 * @param converter the converter to be registered
	 */
	public static <C> void register(Class<C> clazz, Converter<C> converter) {
		CONVERTERS.put(clazz, converter);
		if (clazz.isPrimitive()) {
			CONVERTERS.put(PRIMITIVES_MAPPING.get(clazz), converter);
		}
	}

	/**
	 * Unregister class.
	 * 
	 * @param <C> the generic class type to be unregistered
	 * @param clazz the class which should be unregistered
	 */
	public static <C> void unregister(Class<C> clazz) {
		CONVERTERS.remove(clazz);
		if (clazz.isPrimitive()) {
			CONVERTERS.remove(PRIMITIVES_MAPPING.get(clazz));
		}
	}

	/**
	 * Return true if specific type can be converted from and to string.
	 * 
	 * @param type the type to be checked
	 * @return True if object of given type can be converted, false otherwise
	 */
	public static boolean canConvert(Class<?> type) {
		init();
		return CONVERTERS.get(type) != null;
	}

	/**
	 * Convert object to string.
	 * 
	 * @param object the object to be converted
	 * @return String representation of given object
	 */
	public static final String toString(Object object) {

		init();

		Class<?> clazz = object.getClass();

		@SuppressWarnings("unchecked")
		Converter<Object> cnv = (Converter<Object>) CONVERTERS.get(clazz);

		if (cnv == null) {
			throw new IllegalArgumentException(String.format("Translator for %s not found", clazz));
		}

		return cnv.toString(object);
	}

	/**
	 * Convert string to object.
	 * 
	 * @param clazz the type of object to be created
	 * @param string the string to be converted to specific object
	 * @return Object of the class given in the argument
	 */
	public static final Object toObject(Class<?> clazz, String string) {

		init();

		Converter<?> cnv = CONVERTERS.get(clazz);
		if (cnv == null) {
			throw new IllegalArgumentException(String.format("Translator for %s not found", clazz));
		}

		return cnv.toObject(string);
	}

}
