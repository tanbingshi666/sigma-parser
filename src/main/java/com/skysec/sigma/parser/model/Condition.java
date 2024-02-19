package com.skysec.sigma.parser.model;

import lombok.Data;

@Data
public class Condition {

    private String name;

    private String operator;

    private Condition pairCondition;

    private String notCondition;

    public Condition(String name, String notCondition) {
        this.name = name;
        this.notCondition = notCondition;
    }

}
