package com.skysec.sigma.parser.model;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class Condition {

    private String name;

    private String operator;

    private String peerOperator;

    private String not;

    private Condition nextCondition;

    private Condition peerCondition;

    public Condition(String name) {
        this.name = name;
    }

}
