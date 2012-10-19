package com.github.sarxos.securetoken.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.github.sarxos.securetoken.CipherType;


@Inherited
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE })
public @interface TokenEntity {

	/**
	 * Return string to be used as token delimiter, by default this is single #
	 * char.
	 * 
	 * @return Token delimiter
	 */
	String delimiter() default "#";

	/**
	 * Cipher which should be used to encode entity, no-operation cipher by
	 * default (which does not encode/decode).
	 * 
	 * @return Cipher to be used
	 */
	CipherType cipher() default CipherType.NOOP;
}
