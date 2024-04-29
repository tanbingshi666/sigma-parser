package com.skysec.sigma.parser.model;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * one sigma detection
 */
@Data
public class Detection {

    private String fieldName;
    private final List<String> values = new ArrayList<>();

    private Boolean isMatchAll = false;
    private final List<ModifierType> modifiers = new ArrayList<>();

    public void addModifier(ModifierType modifier) {
        this.modifiers.add(modifier);
    }

    public void addValue(String value) {
        this.values.add(value);
    }

    /**
     * 检测 detection 与 condition 对应 value 是否匹配
     */
    public boolean match(Condition condition, JsonNode sourceValue) {

        int matchCount = 0;

        for (String detectionValue : values) {
            // 可能检测值为数组并且 match all
            if (sourceValue.isArray()) {
                for (JsonNode node : sourceValue) {
                    matchCount = checkValue(matchCount, detectionValue, node.asText());
                }
            } else {
                matchCount = checkValue(matchCount, detectionValue, sourceValue.asText());
            }
        }

        // 可能存在多个 modifier 并且存在 ALL 这种 modifier 情况下
        if (isMatchAll) {
            return matchCount == values.size();
        } else {
            return matchCount > 0;
        }

    }

    private int checkValue(int matchCount, String detectionValue, String value) {
        // detection 存在 modifier 情况下
        if (modifiers.size() > 0) {
            for (ModifierType modifier : modifiers) {
                switch (modifier) {
                    case ALL:
                        break;
                    case CONTAINS:
                    case STARTS_WITH:
                    case ENDS_WITH:
                        if (value.matches(detectionValue)) {
                            matchCount++;
                        }
                        break;
                    case REGEX:
                        if (checkRegex(detectionValue, value)) {
                            matchCount++;
                        }
                        break;
                    default:
                        throw new UnsupportedOperationException("暂时不支持 detection 中 modifier 类型为 " + modifier.name());
                }
            }
        } else if (value.matches(detectionValue)) {
            matchCount++;
        }

        return matchCount;
    }

    private boolean checkRegex(String detectionValue, String value) {
        Pattern pattern = Pattern.compile(detectionValue);
        Matcher matcher = pattern.matcher(value);
        return matcher.find();
    }

}
