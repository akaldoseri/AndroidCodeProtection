package com.example.codeprotectiondemo;

import android.util.Log;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import dalvik.system.DexClassLoader;
import dalvik.system.InMemoryDexClassLoader;

// https://erev0s.com/blog/3-ways-for-dynamic-code-loading-in-android/
public class CustomClassLoader extends ClassLoader {

    String code;
    @Override
    public Class findClass(String name) throws ClassNotFoundException {

        byte[] b = Base64.getDecoder().decode(code);
        return defineClass(name, b, 0, b.length); // return file length and byte (size) of file
    }

    public void loadCode(String code){
        this.code = code;
        byte[] buffer = Base64.getDecoder().decode(code);
        ByteBuffer btBuffer = ByteBuffer.wrap(buffer);
        InMemoryDexClassLoader lder = new InMemoryDexClassLoader(btBuffer, this.getParent());
        Class<?>  mt = null;
        try {
            mt = lder.loadClass("com.example.sorting.Sorting");
            Method checkMethodInMemory = mt.getMethod("Run");
            checkMethodInMemory.invoke(mt);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
    }

}
