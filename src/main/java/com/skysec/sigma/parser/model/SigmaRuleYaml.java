package com.skysec.sigma.parser.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.util.List;
import java.util.Map;

/**
 * sigma-rule 定义类
 * 参考官方文档: https://sigmahq.io/sigma-specification/Sigma_specification.html
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class SigmaRuleYaml {

    // required
    private String title;

    // optional
    private String id;

    // optional
    private String status;

    // optional
    private String description;

    // optional
    private String license;

    // optional
    private String author;

    // optional
    private List<String> references;

    // optional
    private String date;

    // optional
    private String modified;

    // optional
    private List<String> tags;

    // required
    private LogSource logsource;

    // required
    private Map<String, Object> detection;

    // optional
    private List<String> falsepositives;

    // optional
    private String level;
}
