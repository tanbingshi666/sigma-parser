package com.skysec.sigma.parser;

import cn.hutool.log.Log;
import cn.hutool.log.dialect.console.ConsoleLog;
import com.fasterxml.jackson.databind.JsonNode;
import com.skysec.sigma.parser.exception.ConditionErrorException;
import com.skysec.sigma.parser.model.Condition;
import com.skysec.sigma.parser.model.Detection;
import com.skysec.sigma.parser.model.SigmaDetection;
import com.skysec.sigma.parser.utils.StringUtils;

import java.util.*;

public class ConditionManager {

    public static final String OPEN = "(";
    public static final String CLOSE = ")";
    public static final String NOT = "not";
    public static final String AND = "and";
    public static final String OR = "or";
    public static final String SPACE = " ";

    public static final String IN_ONE = "1 of ";
    public static final String IN_ALL = "all of ";

    private final Log console = new ConsoleLog(ConditionManager.class);

    private final List<Condition> conditions = new ArrayList<>();

    private final String condition;

    public ConditionManager(String condition) {
        this.condition = condition;
    }

    public boolean parse(Map<String, SigmaDetection> sigmaDetections,
                         JsonNode valueJson) throws Exception {
        // 检查表达式是否存在 () 并匹配
        int[] match = new int[condition.length()];
        if (!checkBracketAndMarking(condition, match)) {
            throw new ConditionErrorException("解析 condition 表达式中的括号不匹配...");
        }

        return doParse(sigmaDetections, condition, 0, condition.length(), match, valueJson);
    }

    private boolean doParse(Map<String, SigmaDetection> sigmaDetections,
                            String expression,
                            int begin,
                            int end,
                            int[] match,
                            JsonNode valueJson) {
        String operator = null;
        String eval = "";
        String not = null;

        boolean result = true;
        for (int i = begin; i < end; i++) {
            boolean isMatch;
            // 表示遇到 () 表达式 需要提取对应的表达式进行递归
            if (expression.charAt(i) == '(') {
                int r = match[i];
                isMatch = doParse(sigmaDetections, expression.trim(), i + 1, r, match, valueJson);
                // 判断当前 condition 前面是否存在操作符 如果存在则执行计算
                if (operator != null) {
                    result = calculate(result, isMatch, operator);
                    operator = null;
                } else {
                    // 可能 condition: ((a and b) or c) and d 情况下 先执行 isMatch = a and b
                    result = isMatch;
                }
                // 移动 i 到对应的包括结束下标
                i = r + 1;
            } else if (SPACE.equals(String.valueOf(expression.charAt(i)))) {
                // 匹配对应的 detection 中 fieldName
                if (sigmaDetections.containsKey(eval.trim())) {
                    Condition condition = new Condition(eval.trim());
                    // 可能存在 not selection 场景
                    if (not != null) {
                        condition.setNot(not);
                        not = null;
                    }
                    // 执行某个 detection 的匹配规则
                    isMatch = doMatch(sigmaDetections, condition, valueJson, true);

                    // 判断当前 condition 前面是否存在操作符 如果存在则执行计算
                    if (operator != null) {
                        result = calculate(result, isMatch, operator);
                        operator = null;
                    } else {
                        result = isMatch;
                    }

                    eval = "";
                } else if (AND.equals(eval.trim()) || OR.equals(eval.trim())) {
                    operator = eval;
                    eval = "";
                } else if (NOT.equals(eval.trim())) {
                    not = eval;
                    eval = "";
                } else {
                    // 1 of 或者 all of 情况下 需要拼接空格
                    eval = eval.concat(String.valueOf(expression.charAt(i)));
                    if ((eval.trim().startsWith(IN_ONE) && eval.length() > IN_ONE.length())
                            || (eval.trim().startsWith(IN_ALL) && eval.length() > IN_ALL.length())) {
                        Condition condition = new Condition(eval);
                        if (not != null) {
                            condition.setNot(not);
                            not = null;
                        }
                        isMatch = doMatch(sigmaDetections, condition, valueJson, false);
                        if (operator != null) {
                            result = calculate(result, isMatch, operator);
                            operator = null;
                        } else {
                            result = isMatch;
                        }

                        eval = "";
                    }
                }
            } else {
                eval = eval.concat(String.valueOf(expression.charAt(i)));
            }
        }

        // 计算最后一个 detection 确保 eval 有值
        if (!StringUtils.isEmpty(eval.trim())) {
            Condition condition = new Condition(eval.trim());
            if (not != null) {
                condition.setNot(not);
            }
            boolean isMatch = false;
            if (sigmaDetections.containsKey(eval.trim())) {
                isMatch = doMatch(sigmaDetections, condition, valueJson, true);
            } else {
                isMatch = doMatch(sigmaDetections, condition, valueJson, false);
            }

            if (operator != null) {
                result = calculate(result, isMatch, operator);
            } else {
                result = isMatch;
            }
        }

        return result;
    }

    private boolean calculate(boolean result, boolean isMatch, String operator) {
        switch (operator) {
            case AND:
                return result && isMatch;
            case OR:
                return result || isMatch;
            default:
                return false;
        }
    }

    private boolean doMatch(Map<String, SigmaDetection> sigmaDetections,
                            Condition condition,
                            JsonNode valueJson,
                            boolean isMatchFiledName) {
        boolean isMatch = false;
        int validDetectionCount = 0;
        if (isMatchFiledName) {
            SigmaDetection sigmaDetection = sigmaDetections.get(condition.getName());
            /**
             * keyword 的情况下 比如
             * detection:
             *     keywords:
             *         - 'Adfind'
             *         - 'ASP/BackDoor'
             *         - 'ATK/'
             *     condition: keywords
             */
            if (sigmaDetection.getDetections().size() == 1 && sigmaDetection.getDetections().get(0).getFieldName() == null) {
                Detection detection = sigmaDetection.getDetections().get(0);
                for (String value : detection.getValues()) {
                    if (valueJson.toString().contains(value)) {
                        isMatch = true;
                        break;
                    }
                }
            } else {
                validDetectionCount = getValidDetectionCount(condition, valueJson, sigmaDetection);
                isMatch = validDetectionCount == sigmaDetection.getDetections().size();
            }
        } else if (condition.getName().startsWith(ConditionParser.IN_ONE)) {
            // 1 of selection* 情况下
            String regexDetectionName = buildRegexDetectionName(condition.getName().trim().split(SPACE)[2]);
            Map<String, SigmaDetection> matchDetectionNames = findRegexDetectionNames(sigmaDetections, regexDetectionName);

            for (Map.Entry<String, SigmaDetection> entry : matchDetectionNames.entrySet()) {
                validDetectionCount += getValidDetectionCount(condition, valueJson, entry.getValue());
            }

            isMatch = validDetectionCount > 0;
        } else if (condition.getName().startsWith(ConditionParser.IN_ALL)) {
            // all of selection* 情况下
            String regexDetectionName = buildRegexDetectionName(condition.getName().trim().split(SPACE)[2]);
            Map<String, SigmaDetection> matchDetectionNames = findRegexDetectionNames(sigmaDetections, regexDetectionName);

            for (Map.Entry<String, SigmaDetection> entry : matchDetectionNames.entrySet()) {
                validDetectionCount += getValidDetectionCount(condition, valueJson, entry.getValue());
            }

            isMatch = validDetectionCount == matchDetectionNames.size();
        }

        // 如果 condition 存在 not 情况下 比如 condition: not selection
        if (!StringUtils.isEmpty(condition.getNot())) {
            return !isMatch;
        }
        return isMatch;
    }

    /**
     * condition 中可能存在 1 of xxx 或者 all of xxx
     * 需要根据 xxx (转换为正则表达式) 匹配对应的 detectionName (可能符合多个)
     */
    private Map<String, SigmaDetection> findRegexDetectionNames(Map<String, SigmaDetection> sigmaDetections,
                                                                String regexDetectionName) {
        Map<String, SigmaDetection> resultSigmaDetections = new HashMap<>();
        for (Map.Entry<String, SigmaDetection> entry : sigmaDetections.entrySet()) {
            if (entry.getKey().matches(regexDetectionName)) {
                resultSigmaDetections.put(entry.getKey(), entry.getValue());
            }
        }
        return resultSigmaDetections;
    }

    /**
     * 将 regexDetectionName 转换为正则表达式
     */
    private String buildRegexDetectionName(String regexDetectionName) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < regexDetectionName.length(); ++i) {
            final char c = regexDetectionName.charAt(i);
            switch (c) {
                case '*':
                    out.append(".*");
                    break;
                case '?':
                    out.append('.');
                    break;
                case '.':
                    out.append("\\.");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                default:
                    out.append(c);
            }
        }
        return out.toString();
    }

    /**
     * 可能一个 detectionName 存在多个 detection 比如如下:
     * selection:
     * - query|contains: 'hello'
     * - select: 'dns'
     * 故检测统计次数
     */
    private int getValidDetectionCount(Condition condition, JsonNode data, SigmaDetection sigmaDetection) {
        int validDetectionCount = 0;
        /**
         * 可能一个 detection 对应多个条件 比如如下:
         * detection:
         *     selection:
         *         Provider_Name: 'Application Error'
         *         EventID: 1000
         *         Data|contains|all:
         *             - 'MsMpEng.exe'
         *             - 'mpengine.dll'
         *     condition: selection
         * 或者
         * detection:
         *     selection:
         *         - EventID: 4728
         *         - Image: cmd.exe
         *     condition: selection
         * 因此需要检查该 detection 对应的所有 fileName 匹配个数
         */
        for (Detection detection : sigmaDetection.getDetections()) {
            String name = detection.getFieldName();

            // 判断数据源是否存在对应的字段数据
            if (data.has(name)) {
                JsonNode sourceValue = data.get(name);
                if (validDetection(detection, condition, sourceValue)) {
                    validDetectionCount++;
                }
            }
        }
        return validDetectionCount;
    }

    /**
     * 执行检测
     */
    private boolean validDetection(Detection detection, Condition condition, JsonNode sourceValue) {
        return detection.match(condition, sourceValue);
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

    public void addCondition(Condition condition) {
        conditions.add(condition);
    }

    public List<Condition> getConditions() {
        return conditions;
    }

}
