package com.skysec.sigma.parser.model;

import java.util.HashMap;
import java.util.Map;

public enum ModifierType {

    CONTAINS("contains"),

    ALL("all"),

    ENDS_WITH("endswith"),

    STARTS_WITH("startswith"),

    REGEX("re");

    private final String value;

    ModifierType(String value) {
        this.value = value;
    }

    private static final Map<String, ModifierType> lookup = new HashMap<>();

    static {
        for (ModifierType t : ModifierType.values()) {
            lookup.put(t.value, t);
        }
    }

    public static ModifierType getEnum(String value) {
        return lookup.get(value);
    }

}
