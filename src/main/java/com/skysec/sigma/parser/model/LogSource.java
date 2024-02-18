package com.skysec.sigma.parser.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

@JsonIgnoreProperties(ignoreUnknown = true)

@Data
public class LogSource {

    private String category;

    private String product;

    private String service;

}
