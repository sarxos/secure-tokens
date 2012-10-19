package com.github.sarxos.securetoken;

/**
 * Abstraction for translating string to any other type.
 * 
 * @author Bartosz Firyn (bfiryn)
 */
public interface Converter<T> {

	/**
	 * Converts string to object.
	 * 
	 * @param string the string to be converted to object
	 * @return Object
	 */
	T toObject(String string);

	/**
	 * Converts object to string.
	 * 
	 * @param object the object to be converted to string.
	 * @return String
	 */
	String toString(T object);

}