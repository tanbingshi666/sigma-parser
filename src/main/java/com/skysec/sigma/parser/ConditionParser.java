package com.skysec.sigma.parser;

import cn.hutool.log.Log;
import cn.hutool.log.dialect.console.ConsoleLog;
import com.skysec.sigma.parser.exception.ConditionErrorException;
import com.skysec.sigma.parser.model.SigmaRuleYaml;

public class ConditionParser {

    private final Log console = new ConsoleLog(ConditionParser.class);

    public static final String OPEN = "(";
    public static final String CLOSE = ")";
    public static final String NOT = "not";
    public static final String AND = "and";
    public static final String OR = "or";
    public static final String SPACE = " ";

    public static final String IN_ONE = "1 of ";
    public static final String IN_ALL = "all of ";

    public ConditionManager parseCondition(SigmaRuleYaml sigmaRuleYaml) throws Exception {

        ConditionManager conditionManager;
        try {
            // 具体 condition 说明参考：https://sigmahq.io/docs/basics/conditions.html
            String condition = sigmaRuleYaml.getDetection().get("condition").toString();
            conditionManager = new ConditionManager(condition);
        } catch (Exception e) {
            e.printStackTrace();
            throw new ConditionErrorException("解析 condition 错误, 请检查文件是否编写正确...");
        }

        return conditionManager;
    }
}
