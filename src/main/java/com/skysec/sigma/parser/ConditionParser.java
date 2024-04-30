package com.skysec.sigma.parser;

import cn.hutool.log.Log;
import cn.hutool.log.dialect.console.ConsoleLog;
import com.skysec.sigma.parser.exception.ConditionErrorException;
import com.skysec.sigma.parser.model.Condition;
import com.skysec.sigma.parser.model.SigmaDetection;
import com.skysec.sigma.parser.model.SigmaRuleYaml;

import java.util.Arrays;
import java.util.Map;

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

    // 临时变量
    String eval = "";
    String operator;
    String not;
    Condition currentCondition = null;

    /**
     * 解析 condition
     *
     * @param sigmaDetections 主要判断 condition 的 name 是否存在于 detections 集合
     * @param sigmaRuleYaml   sigma rule yaml 文件解析
     */
    public ConditionManager parseCondition(Map<String, SigmaDetection> sigmaDetections,
                                           SigmaRuleYaml sigmaRuleYaml) throws Exception {

        ConditionManager conditionManager = new ConditionManager();

        try {
            // 具体 condition 说明参考：https://sigmahq.io/docs/basics/conditions.html
            /**
             * 基于链表的方式连接整个 Condition
             * 比如 condition: a and (b or (c and d) ) or e
             *
             * Condition(a,and) -> Condition(b,or) -> Condition(e,null)
             *                         |
             *                     Condition(c,and)
             *                         |
             *                     Condition(d,null)
             */
            String condition = sigmaRuleYaml.getDetection().get("condition").toString();
            conditionManager.addCondition(parse(sigmaDetections, condition));
        } catch (Exception e) {
            throw new ConditionErrorException("解析 condition 错误, 请检查文件是否编写错误...");
        }

        return conditionManager;
    }

    private Condition parse(Map<String, SigmaDetection> sigmaDetections,
                            String expression) throws Exception {
        // 检查表达式是否存在 () 并匹配
        int[] match = new int[expression.length()];
        if (!checkBracketAndMarking(expression, match)) {
            throw new ConditionErrorException("解析 condition 表达式中的括号不匹配...");
        }

        return calculate(sigmaDetections, expression.trim(), 0, expression.length(), match, false);
    }

    private Condition calculate(Map<String, SigmaDetection> sigmaDetections,
                                String expression,
                                int begin, int end,
                                int[] match, boolean isPeer) {
        Condition resultCondition = null;
        Condition currentCondition = null;
        Condition peerCondition = null;
        for (int i = begin; i < end; i++) {
            // 表示遇到 () 表达式 需要提取对应的表达式进行递归
            if (expression.charAt(i) == '(') {
                int r = match[i];
                Condition condition = calculate(sigmaDetections, expression.trim(), i + 1, r, match, true);
                setNot(condition);
                if (resultCondition == null) {
                    resultCondition = condition;
                } else {
                    currentCondition.setNextCondition(condition);
                }
                currentCondition = condition;
                i = r + 1;
            } else if (SPACE.equals(String.valueOf(expression.charAt(i)))) {
                // 匹配对应的 detection 中 fieldName
                if (sigmaDetections.containsKey(eval)) {
                    Condition condition = new Condition(eval);
                    setNot(condition);
                    if (resultCondition == null) {
                        resultCondition = condition;
                    } else if (currentCondition != null) {
                        if (isPeer) {
                            if (peerCondition != null) {
                                peerCondition.setPeerCondition(condition);
                            } else {
                                currentCondition.setPeerCondition(condition);
                            }
                            peerCondition = condition;
                        } else {
                            currentCondition.setNextCondition(condition);
                        }
                    }
                    currentCondition = condition;
                    eval = "";
                } else if (AND.equals(eval) || OR.equals(eval)) {
                    if (isPeer) {
                        setPeerOperator(currentCondition, eval);
                    } else {
                        setOperator(currentCondition, eval);
                    }
                    eval = "";
                } else if (NOT.equals(eval)) {
                    not = eval;
                    eval = "";
                } else {
                    // 1 of 或者 all of 情况下 需要拼接空格
                    eval = eval.concat(String.valueOf(expression.charAt(i)));
                    if ((eval.startsWith(IN_ONE) && eval.length() > IN_ONE.length())
                            || (eval.startsWith(IN_ALL) && eval.length() > IN_ALL.length())) {
                        Condition condition = new Condition(eval);
                        setNot(condition);
                        if (resultCondition == null) {
                            resultCondition = condition;
                        } else if (currentCondition != null) {
                            if (isPeer) {
                                if (peerCondition != null) {
                                    peerCondition.setPeerCondition(condition);
                                } else {
                                    currentCondition.setPeerCondition(condition);
                                }
                                peerCondition = condition;
                            } else {
                                currentCondition.setNextCondition(condition);
                            }
                        }
                        currentCondition = condition;
                        eval = "";
                    }
                }
            } else {
                eval = eval.concat(String.valueOf(expression.charAt(i)));
            }
        }

        // the last condition
        if (eval.length() > 0) {
            Condition condition = new Condition(eval);
            setNot(condition);
            if (resultCondition == null) {
                resultCondition = condition;
            } else if (currentCondition != null) {
                if (isPeer) {
                    if (peerCondition != null) {
                        peerCondition.setPeerCondition(condition);
                    } else {
                        currentCondition.setPeerCondition(condition);
                    }
                } else {
                    currentCondition.setNextCondition(condition);
                }
            }
            eval = "";
        }

        return resultCondition;
    }

    private void setOperator(Condition condition, String eval) {
        if (AND.equals(eval) || OR.equals(eval)) {
            condition.setOperator(eval);
        }
    }

    private void setPeerOperator(Condition condition, String eval) {
        if (AND.equals(eval) || OR.equals(eval)) {
            condition.setPeerOperator(eval);
        }
    }

    private void setNot(Condition condition) {
        if (not != null) {
            condition.setNot(not);
            not = null;
        }
    }

    /**
     * eg:
     * expression = 1*(a-b+(c*d))-0
     * match -> [0, 0, 12, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0]
     */
    private boolean checkBracketAndMarking(String expression, int[] match) {
        Arrays.fill(match, 0);

        int[] stack = new int[match.length];
        int top = -1;
        for (int i = 0; i < expression.length(); i++) {
            switch (expression.charAt(i)) {
                case '(':
                    stack[++top] = i;
                    break;
                case ')':
                    if (top < 0) return false;
                    match[stack[top]] = i;
                    --top;
                    break;
            }
        }
        return top < 0;
    }

}
