package com.skysec.sigma.parser;

import cn.hutool.log.Log;
import cn.hutool.log.dialect.console.ConsoleLog;
import com.skysec.sigma.parser.model.Condition;
import com.skysec.sigma.parser.model.SigmaRuleYaml;
import com.skysec.sigma.parser.utils.StringUtils;

import java.text.CharacterIterator;
import java.text.StringCharacterIterator;

public class ConditionParser {

    private final Log console = new ConsoleLog(ConditionParser.class);

    public static final String OPEN_PAREN = "(";
    public static final String CLOSE_PAREN = ")";
    public static final String NOT = "not";
    public static final String AND = "and";
    public static final String OR = "or";
    public static final String SPACE = " ";

    // 临时字符串
    private String temp = "";
    private Condition currentCondition;

    public ConditionManager parseCondition(SigmaRuleYaml sigmaRuleYaml) {

        ConditionManager conditionManager = new ConditionManager();

        String condition = sigmaRuleYaml.getDetection().get("condition").toString();
        if (!StringUtils.isEmpty(condition)) {
            CharacterIterator it = new StringCharacterIterator(condition);

            // todo 目前只考虑 AND 以及 OR 情况
            /**
             * 情况一: condition: selection
             * 情况二: condition: selection1 AND selection2
             * 情况三: condition: selection1 OR selection2
             */
            while (it.current() != CharacterIterator.DONE) {
                String currentChar = Character.toString(it.current());
                switch (currentChar) {
                    case SPACE:
                        if (!StringUtils.isEmpty(temp)) {
                            evaluateString(conditionManager, temp);
                        }
                        temp = "";
                        break;
                    default:
                        temp = temp.concat(currentChar);
                        break;
                }

                it.next();
            }

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
            default:
                if (currentCondition == null) {
                    currentCondition = new Condition(eval);
                    conditionManager.addCondition(currentCondition);
                } else {
                    Condition newCondition = new Condition(eval);
                    currentCondition.setPairCondition(newCondition);
                    currentCondition = newCondition;
                }
                break;
        }

    }
}
