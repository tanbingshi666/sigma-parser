package com.skysec.sigma.parser.model;

import lombok.Data;

@Data
public class Condition {

    private String name;

    private String not;

    public Condition(String name) {
        this.name = name;
    }

}
