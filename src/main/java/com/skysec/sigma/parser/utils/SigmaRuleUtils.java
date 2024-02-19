package com.skysec.sigma.parser.utils;

import cn.hutool.log.Log;
import cn.hutool.log.dialect.console.ConsoleLog;
import com.fasterxml.jackson.databind.JsonNode;
import com.skysec.sigma.parser.ConditionParser;
import com.skysec.sigma.parser.DetectionManager;
import com.skysec.sigma.parser.model.Condition;
import com.skysec.sigma.parser.model.Detection;
import com.skysec.sigma.parser.model.SigmaDetection;
import com.skysec.sigma.parser.model.SigmaRule;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * sigma rule 检测工具
 */
public class SigmaRuleUtils {

    private final Log console = new ConsoleLog(SigmaRuleUtils.class);

    /**
     * 检测 sigma rule
     */
    public boolean isValid(SigmaRule sigmaRule, JsonNode data) {
        if (sigmaRule != null) {
            return checkCondition(sigmaRule, data);
        }
        console.error("非法的 Sigma Rule, 也即检测到 Sigma Rule 为 null");
        return false;
    }

    private boolean checkCondition(SigmaRule sigmaRule, JsonNode data) {
        List<Condition> conditions = sigmaRule.getConditionManager().getConditions();
        // condition 从左开始遍历 故取左边第一个
        return checkCondition(conditions.get(0), sigmaRule.getDetectionManager(), data);
    }

    private boolean checkCondition(Condition condition, DetectionManager detectionManager, JsonNode data) {

        boolean pairConditionResult;

        // condition 存在 and or 语句情况下
        if (condition.getPairCondition() != null) {
            pairConditionResult = checkCondition(condition.getPairCondition(), detectionManager, data);

            // 如果 pairConditionResult 检测为 true 并且父 condition 的操作符为 or 则不需要检测父 condition 直接返回 true
            if (pairConditionResult && ConditionParser.OR.equals(condition.getOperator())) {
                return true;
            } else if (ConditionParser.OR.equals(condition.getOperator())) {
                return checkParentCondition(condition, detectionManager, data);
            } else { // and
                return pairConditionResult && checkParentCondition(condition, detectionManager, data);
            }
        }

        // condition 只存在一个条件语句 比如 condition: selection
        return checkParentCondition(condition, detectionManager, data);
    }

    /**
     * 检测 condition 语句中单个 detectionName
     */
    private boolean checkParentCondition(Condition condition, DetectionManager detectionManager, JsonNode data) {

        int validDetectionCount = 0;
        boolean isCheckMatch = false;

        // 直接匹配到 detectionName 情况下
        SigmaDetection sigmaDetection = detectionManager.getSigmaDetectionByName(condition.getName());
        if (sigmaDetection != null) {
            validDetectionCount = getValidDetectionCount(condition, data, validDetectionCount, sigmaDetection);
            isCheckMatch = validDetectionCount == sigmaDetection.getDetections().size();
        } else if (condition.getName().startsWith(ConditionParser.IN_ONE)) {
            // 1 of selection* 情况下

            String regexName = condition.getName().trim().split(ConditionParser.SPACE)[2];
            Map<String, SigmaDetection> regexNameSigmaDetections = findRegexNameSigmaDetections(detectionManager, regexName);
            for (Map.Entry<String, SigmaDetection> entry : regexNameSigmaDetections.entrySet()) {
                validDetectionCount = getValidDetectionCount(condition, data, validDetectionCount, entry.getValue());
            }
            isCheckMatch = validDetectionCount > 0;
        } else if (condition.getName().startsWith(ConditionParser.IN_ALL)) {
            // all of selection* 情况下

            String regexName = condition.getName().trim().split(ConditionParser.SPACE)[2];
            Map<String, SigmaDetection> regexNameSigmaDetections = findRegexNameSigmaDetections(detectionManager, regexName);
            for (Map.Entry<String, SigmaDetection> entry : regexNameSigmaDetections.entrySet()) {
                validDetectionCount = getValidDetectionCount(condition, data, validDetectionCount, entry.getValue());
            }
            isCheckMatch = validDetectionCount == regexNameSigmaDetections.size();
        } else {
            console.info("condition 中 name 在 detection 找不到对应的信息...");
            return false;
        }

        // 如果 condition 存在 not 则取反即可
        if (ConditionParser.NOT.equals(condition.getNotCondition())) {
            isCheckMatch = !isCheckMatch;
        }

        return isCheckMatch;
    }

    /**
     * 可能一个 detectionName 存在多个 detection 比如如下:
     * selection:
     * - query|contains: 'hello'
     * - select: 'dns'
     * 故检测统计次数
     */
    private int getValidDetectionCount(Condition condition, JsonNode data, int validDetectionCount, SigmaDetection sigmaDetection) {
        for (Detection detection : sigmaDetection.getDetections()) {
            String name = detection.getName();

            // 判断数据源是否存在对应的字段数据
            if (data.has(name)) {
                JsonNode sourceValue = data.get(name);
                if (validDetection(detection, condition, sourceValue)) {
                    validDetectionCount++;
                }
            } else {
                console.info("数据源中不存在字段为 {} 相关数据...", name);
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
     * condition 中可能存在 1 of xxx 或者 all of xxx
     * 需要根据 xxx (转换为正则表达式) 匹配对应的 detectionName (可能符合多个)
     */
    private Map<String, SigmaDetection> findRegexNameSigmaDetections(DetectionManager detectionManager, String regexName) {
        Map<String, SigmaDetection> sigmaDetections = new HashMap<>();
        for (Map.Entry<String, SigmaDetection> entry : detectionManager.getSigmaDetections().entrySet()) {
            if (entry.getKey().matches(buildRegexName(regexName))) {
                sigmaDetections.put(entry.getKey(), entry.getValue());
            }
        }
        return sigmaDetections;
    }

    /**
     * 将 regexName 转换为正则表达式
     */
    private String buildRegexName(String regexName) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < regexName.length(); ++i) {
            final char c = regexName.charAt(i);
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

}
