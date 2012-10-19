package com.github.sarxos.securetoken;

import java.math.BigDecimal;
import java.util.EnumSet;

import org.junit.Test;

import com.github.sarxos.securetoken.annotation.TokenPart;


public class TokenizerTest {

	public static class Data implements Token {

		@TokenPart("c")
		private BigDecimal c = new BigDecimal("1234567890");

		public BigDecimal getC() {
			return c;
		}

		public void setC(BigDecimal c) {
			this.c = c;
		}
	}

	public static class TokenTest extends Data {

		@TokenPart("a")
		private String a;

		@Override
		public String toString() {
			return a + " " + getC();
		}

		public void setA(String a) {
			this.a = a;
		}
	}

	@Test
	public void test_tokenize() {

		String secret = "test1234";
		String a = "ABBA";
		BigDecimal c = new BigDecimal("123456789");

		int n = 10000;
		long p = 0;
		long k = 0;

		EnumSet<CipherType> types = EnumSet.allOf(CipherType.class);
		for (CipherType type : types) {

			TokenTest tt = new TokenTest();
			tt.setA(a);
			tt.setC(c);

			p = System.currentTimeMillis();
			String token = null;
			for (int i = 0; i < n; i++) {
				token = Tokenizer.tokenize(tt, type, secret);
			}
			k = System.currentTimeMillis();

			System.out.println(String.format("- %12s tok %5d ms: %s", type.getAlgorithm(), k - p, token));

			p = System.currentTimeMillis();
			TokenTest test = null;
			for (int i = 0; i < n; i++) {
				test = Tokenizer.objectify(TokenTest.class, token, type, secret);
			}
			k = System.currentTimeMillis();

			System.out.println(String.format("- %12s obj %5d ms: %s", type.getAlgorithm(), k - p, test));
		}
	}

	public static class Example implements Token {

		/**
		 * Some kind of secret data.
		 */
		@TokenPart("id")
		protected int id = 4;

		/**
		 * Some other kind of secret data 2.
		 */
		@TokenPart("sec")
		protected String secret = "secret.information.is.here";

		/**
		 * Computer Serial Number
		 */
		@TokenPart("sn")
		protected String sn = Hardware.getSerialNumber();

		// setters/getters
	}

	public static void main(String[] args) {

		Example example = new Example();
		CipherType cipher = CipherType.NOOP;
		String password = "secret password";

		String token = Tokenizer.tokenize(example, cipher, password);

		System.out.println("token:  " + token);

		Example checkme = Tokenizer.objectify(Example.class, token, cipher, password);

		System.out.println("id:     " + checkme.id);
		System.out.println("secret: " + checkme.secret);
		System.out.println("sn:     " + checkme.sn);
	}
}
