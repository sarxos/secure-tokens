package com.github.sarxos.securetoken.impl;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;


public class Reflector {

	public static final <T> Constructor<T> getConstructor(Class<T> clazz, Class<?>... types) {
		try {
			return clazz.getConstructor(types);
		} catch (SecurityException e) {
			throw new RuntimeException(e);
		} catch (NoSuchMethodException e) {
			throw new RuntimeException(e);
		}
	}

	public static final <T> T newInstance(Class<T> clazz, Object... args) {
		Class<?>[] types = null;
		if (args != null && args.length > 0) {
			types = new Class<?>[args.length];
			for (int i = 0; i < args.length; i++) {
				types[i] = args[i].getClass();
			}
		}
		Constructor<T> ctor = Reflector.getConstructor(clazz, types);
		if (ctor == null) {
			throw new IllegalArgumentException("Such constructor does not exist");
		}
		try {
			return ctor.newInstance(args);
		} catch (IllegalArgumentException e) {
			throw new RuntimeException(e);
		} catch (InstantiationException e) {
			throw new RuntimeException(e);
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		} catch (InvocationTargetException e) {
			throw new RuntimeException(e);
		}
	}

	public static final Object getValue(Field field, Object parent) {
		try {
			return field.get(parent);
		} catch (IllegalArgumentException e) {
			throw new RuntimeException(e);
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	public static final void setValue(Field field, Object parent, Object value) {
		try {
			field.set(parent, value);
		} catch (IllegalArgumentException e) {
			throw new RuntimeException(e);
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	public static final Object invoke(Method method, Object parent, Object... args) {
		try {
			return method.invoke(parent, args);
		} catch (IllegalArgumentException e) {
			throw new RuntimeException(e);
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		} catch (InvocationTargetException e) {
			throw new RuntimeException(e);
		}
	}

	public static final Object invoke(String name, Class<?>[] types, Object parent, Object... args) {
		Method method = null;
		try {
			method = parent.getClass().getMethod(name, types);
		} catch (SecurityException e) {
			throw new RuntimeException(e);
		} catch (NoSuchMethodException e) {
			throw new RuntimeException(e);
		}
		return invoke(method, parent, args);
	}
}
