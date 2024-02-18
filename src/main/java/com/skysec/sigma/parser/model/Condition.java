package com.skysec.sigma.parser.model;

import lombok.Data;

@Data
public class Condition {

    private String name;

    private String operator;

    private Condition pairCondition;

    public Condition(String name) {
        this.name = name;
    }

}
