package com.skysec.sigma.parser;

import cn.hutool.log.Log;
import cn.hutool.log.dialect.console.ConsoleLog;
import com.skysec.sigma.parser.model.Condition;
import com.skysec.sigma.parser.model.SigmaDetection;
import com.skysec.sigma.parser.model.SigmaRuleYaml;
import com.skysec.sigma.parser.utils.StringUtils;

import java.text.CharacterIterator;
import java.text.StringCharacterIterator;
import java.util.Map;

public class ConditionParser {

    private final Log console = new ConsoleLog(ConditionParser.class);

    public static final String OPEN_PAREN = "(";
    public static final String CLOSE_PAREN = ")";
    public static final String NOT = "not";
    public static final String AND = "and";
    public static final String OR = "or";
    public static final String SPACE = " ";

    public static final String IN_ONE = "1 of ";
    public static final String IN_ALL = "all of ";

    // 临时变量
    private String temp = "";
    private String notCondition;
    private Condition currentCondition;

    /**
     * 解析 condition
     *
     * @param sigmaDetections 主要判断 condition 的 name 是否存在于 detections 集合
     * @param sigmaRuleYaml   sigma rule yaml 文件解析
     */
    public ConditionManager parseCondition(Map<String, SigmaDetection> sigmaDetections,
                                           SigmaRuleYaml sigmaRuleYaml) {

        ConditionManager conditionManager = new ConditionManager();

        String condition = sigmaRuleYaml.getDetection().get("condition").toString();
        if (!StringUtils.isEmpty(condition)) {
            CharacterIterator it = new StringCharacterIterator(condition.trim());

            // todo 目前只考虑 AND, OR, 1 of selection*, all of selection* 情况
            /**
             * 情况一: condition: selection
             * 情况二: condition: selection1 and selection2
             * 情况三: condition: selection1 or selection2
             *
             * 情况四: 1 of selection*
             * 情况五: all of selection* and select
             */
            while (it.current() != CharacterIterator.DONE) {
                String currentChar = Character.toString(it.current());
                if (SPACE.equals(currentChar)) {
                    // 匹配 detection 或者是操作符 (and, or) 或者否定 (not) 情况下
                    if (sigmaDetections.containsKey(temp) || AND.equals(temp) || OR.equals(temp) || NOT.equals(temp)) {
                        evaluateString(conditionManager, temp);
                        temp = "";
                    } else {
                        // 1 of 或者 all of 情况下
                        if ((temp.startsWith(IN_ONE) && temp.length() > IN_ONE.length()) || (temp.startsWith(IN_ALL) && temp.length() > IN_ALL.length())) {
                            evaluateString(conditionManager, temp);
                            temp = "";
                        } else {
                            temp = temp.concat(currentChar);
                        }
                    }
                } else {
                    temp = temp.concat(currentChar);
                }

                it.next();
            }

            // the last part of condition
            if (!StringUtils.isEmpty(temp)) {
                evaluateString(conditionManager, temp);
            }
        }

        return conditionManager;
    }

    private void evaluateString(ConditionManager conditionManager, String eval) {
        switch (eval) {
            case AND:
            case OR:
                currentCondition.setOperator(eval);
                break;
            case NOT:
                notCondition = NOT;
                break;
            default:
                if (currentCondition == null) {
                    currentCondition = new Condition(eval, notCondition);
                    conditionManager.addCondition(currentCondition);
                } else {
                    Condition newCondition = new Condition(eval, notCondition);
                    currentCondition.setPairCondition(newCondition);
                    currentCondition = newCondition;
                }
                notCondition = null;
                break;
        }

    }
}
