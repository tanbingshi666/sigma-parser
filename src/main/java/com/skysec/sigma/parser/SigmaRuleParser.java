package com.skysec.sigma.parser;

import cn.hutool.log.Log;
import cn.hutool.log.dialect.console.ConsoleLog;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.skysec.sigma.parser.model.SigmaRule;
import com.skysec.sigma.parser.model.SigmaRuleYaml;

/**
 * sigma rule 解析入口
 */
public class SigmaRuleParser {

    private final Log console = new ConsoleLog(SigmaRuleParser.class);

    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());

    private final DetectionParser detectionParser;
    private final ConditionParser conditionParser;

    public SigmaRuleParser() {
        this.detectionParser = new DetectionParser();
        this.conditionParser = new ConditionParser();
    }

    /**
     * 解析 yaml 文件
     */
    public SigmaRule parseRule(String rule) throws Exception {
        SigmaRuleYaml sigmaRuleYaml = yamlMapper.readValue(rule, SigmaRuleYaml.class);
        return parseRule(sigmaRuleYaml);
    }

    /**
     * 解析 sigma rule (核心解析 detection 和 condition)
     */
    public SigmaRule parseRule(SigmaRuleYaml sigmaRuleYaml) throws Exception {
        SigmaRule sigmaRule = new SigmaRule();
        sigmaRule.copySigmaRuleProperties(sigmaRuleYaml);

        // 解析 detection
        sigmaRule.setDetectionManager(detectionParser.parseDetections(sigmaRuleYaml));

        // 解析 condition
        sigmaRule.setConditionManager(conditionParser.parseCondition(
                sigmaRuleYaml));

        return sigmaRule;
    }

}
