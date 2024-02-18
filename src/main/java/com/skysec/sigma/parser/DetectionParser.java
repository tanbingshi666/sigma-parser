package com.skysec.sigma.parser;

import cn.hutool.log.Log;
import cn.hutool.log.dialect.console.ConsoleLog;
import com.skysec.sigma.parser.model.Detection;
import com.skysec.sigma.parser.model.ModifierType;
import com.skysec.sigma.parser.model.SigmaDetection;
import com.skysec.sigma.parser.model.SigmaRuleYaml;
import com.skysec.sigma.parser.utils.StringUtils;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 解析 sigma rule 中 detection 属性
 */
public class DetectionParser {

    private final Log console = new ConsoleLog(DetectionParser.class);

    public static final String SEPARATOR = "|";

    public DetectionManager parseDetections(SigmaRuleYaml sigmaRuleYaml) {

        DetectionManager detectionManager = new DetectionManager();

        /**
         * 根据官方文档: https://sigmahq.io/sigma-specification/Sigma_specification.html 格式如下:
         * detection
         *    {search-identifier-1} [optional]
         *      {string-list} [optional]
         *      {map-list} [optional]
         *      {field: value} [optional]
         *    ...
         *    {search-identifier-N} [optional]
         *      {string-list} [optional]
         *      {map-list} [optional]
         *      {field: value} [optional]
         *    condition
         */
        for (Map.Entry<String, Object> entry : sigmaRuleYaml.getDetection().entrySet()) {
            String detectionName = entry.getKey();
            // value 可能是 List 或者 Map 结构
            Object value = entry.getValue();

            if (detectionName.equals("condition") || detectionName.equals("timeframe") || detectionName.equals("fields")) {
                // todo handle separately
                // console.info("sigma rule 中 detection 属性存在对应的条件, 暂时忽略 key = {}, value = {}", detectionName, value);
            } else {
                detectionManager.addSigmaDetection(detectionName, parseDetection(value));
            }
        }

        return detectionManager;
    }

    @SuppressWarnings("unchecked")
    private SigmaDetection parseDetection(Object value) {
        SigmaDetection sigmaDetection = new SigmaDetection();

        // 一般情况下 detectionName 对应的 value 为 List 或者 Map
        if (value instanceof LinkedHashMap) {
            LinkedHashMap<String, Object> searchMap = (LinkedHashMap<String, Object>) value;
            parseMap(sigmaDetection, searchMap);
        } else if (value instanceof ArrayList) {
            List<Object> searchArray = (ArrayList<Object>) value;
            parseList(sigmaDetection, null, searchArray);
        } else {
            console.error("存在未知 detection 类型: " + value.getClass() + " value: " + value + ", 可用类型为 List 或者 Map");
        }

        return sigmaDetection;
    }

    @SuppressWarnings("unchecked")
    private void parseMap(SigmaDetection sigmaDetection, LinkedHashMap<String, Object> searchMap) {
        for (Map.Entry<String, Object> entry : searchMap.entrySet()) {
            if (entry.getValue() instanceof ArrayList) {
                List<Object> searchArray = (ArrayList<Object>) entry.getValue();
                parseList(sigmaDetection, entry.getKey(), searchArray);
            } else if (entry.getValue() instanceof LinkedHashMap) {
                LinkedHashMap<String, Object> searchInnerMap = (LinkedHashMap<String, Object>) entry.getValue();
                parseMap(sigmaDetection, searchInnerMap);
            } else {
                Detection detection = new Detection();

                parseName(detection, entry.getKey());
                parseValue(detection, entry.getValue().toString());

                sigmaDetection.addDetection(detection);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void parseList(SigmaDetection sigmaDetection, String name, List<Object> searchArray) {
        Detection detection = null;

        if (name != null) {
            detection = new Detection();
            parseName(detection, name);
        }

        for (Object searchValue : searchArray) {
            if ((searchValue instanceof LinkedHashMap) || (name == null)) {
                LinkedHashMap<String, Object> searchMap = (LinkedHashMap<String, Object>) searchValue;
                parseMap(sigmaDetection, searchMap);
            } else {
                parseValue(detection, searchValue.toString());
            }
        }

        if (detection != null && detection.getDetectionValues().size() > 0) {
            sigmaDetection.addDetection(detection);
        }
    }

    private void parseName(Detection detection, String name) {
        String parsedName = StringUtils.substringBefore(name, SEPARATOR);

        detection.setName(parsedName);

        if (name.contains(SEPARATOR)) {
            String[] modifiers = name.split("\\" + SEPARATOR);

            Iterator<String> iterator = Arrays.stream(modifiers).iterator();
            while (iterator.hasNext()) {
                ModifierType modifier = ModifierType.getEnum(iterator.next());
                if (modifier == ModifierType.ALL) {
                    detection.setIsMatchAll(true);
                } else if (modifier != null) {
                    detection.addModifier(modifier);
                }
            }
        }

    }

    private void parseValue(Detection detection, String value) {
        if (detection.getModifiers().size() > 0) {
            for (ModifierType modifier : detection.getModifiers()) {
                detection.addValue(buildStringWithModifier(value, modifier));
            }
        } else {
            detection.addValue(sigmaWildcardToRegex(value));
        }
    }

    private String buildStringWithModifier(String value, ModifierType modifier) {

        if (modifier != null) {
            switch (modifier) {
                case STARTS_WITH:
                    return sigmaWildcardToRegex(value) + ".*";
                case CONTAINS:
                    return ".*" + sigmaWildcardToRegex(value) + ".*";
                case ENDS_WITH:
                    return ".*" + sigmaWildcardToRegex(value);
                case REGEX:
                    if (!validRegex(value)) {
                        console.error("Regular expression operator specified " + "but pattern did not compile for value = " + value);
                    }
                    return value;
            }
        }

        return sigmaWildcardToRegex(value);
    }

    private String sigmaWildcardToRegex(String value) {

        StringBuilder out = new StringBuilder();

        for (int i = 0; i < value.length(); ++i) {
            final char c = value.charAt(i);
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

    private boolean validRegex(String regex) {
        try {
            Pattern.compile(regex);
            return true;
        } catch (PatternSyntaxException e) {
            return false;
        }
    }

}
