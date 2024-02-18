package com.skysec.sigma.parser.utils;

public class StringUtils {

    public static boolean isEmpty(CharSequence cs) {
        return cs == null || cs.length() == 0;
    }

    /**
     * 截取 separator 之前的字符串
     */
    public static String substringBefore(String str, String separator) {
        if (!isEmpty(str) && separator != null) {
            if (isEmpty(separator)) {
                return "";
            } else {
                int pos = str.indexOf(separator);
                return pos == -1 ? str : str.substring(0, pos);
            }
        } else {
            return str;
        }
    }

}
