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

import java.util.List;

/**
 * sigma rule 检测工具
 */
public class SigmaRuleCheckUtils {

    private final Log console = new ConsoleLog(SigmaRuleCheckUtils.class);

    /**
     * 检测 sigma rule
     *
     * @param sigmaRule
     * @param data
     * @return
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
        for (Condition condition : conditions) {
            if (checkCondition(condition, sigmaRule.getDetectionManager(), data)) {
                return true;
            }
        }

        return false;
    }

    private boolean checkCondition(Condition condition, DetectionManager detectionManager, JsonNode data) {

        boolean pairConditionResult;

        // condition 存在 and or 等语句情况下
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

    private boolean checkParentCondition(Condition condition, DetectionManager detectionManager, JsonNode data) {

        boolean validDetection = false;

        // 根据 condition 的 name 获取对应的 detection
        SigmaDetection sigmaDetection = detectionManager.getSigmaDetectionByName(condition.getName());

        if (sigmaDetection != null) {
            for (Detection detection : sigmaDetection.getDetections()) {
                String name = detection.getName();

                // 判断数据源是否存在对应的字段数据
                if (data.has(name)) {
                    JsonNode sourceValue = data.get(name);
                    validDetection = validDetection(detection, condition, sourceValue);
                } else {
                    console.info("数据源中不存在字段为 {} 相关数据...", name);
                    return false;
                }
            }

            return validDetection;
        } else {
            console.info("condition 中 name 在 detection 找不到对应的信息...");
        }

        return false;
    }

    private boolean validDetection(Detection detection, Condition condition, JsonNode sourceValue) {
        return detection.match(condition, sourceValue);
    }
}
