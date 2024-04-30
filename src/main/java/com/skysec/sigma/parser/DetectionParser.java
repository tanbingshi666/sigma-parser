package com.skysec.sigma.parser;

import cn.hutool.log.Log;
import cn.hutool.log.dialect.console.ConsoleLog;
import com.skysec.sigma.parser.exception.DetectionErrorException;
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

    public DetectionManager parseDetections(SigmaRuleYaml sigmaRuleYaml) throws Exception {

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
         * 其中 detection 主要有 3 中模式匹配
         * 1 by Keyword：        https://sigmahq.io/docs/basics/rules.html#detection-keyword
         * detection:
         *     keywords:
         *         - 'rm *bash_history'
         *         - 'echo "" > *bash_history'
         *         - 'truncate -s0 *bash_history'
         *         - 'history -c'
         *         - 'history -w'
         *     condition: keywords
         * 2 by Field Value：    https://sigmahq.io/docs/basics/rules.html#detection-and
         * detection:
         *     selection:
         *         EventID: 6416  # and where
         *         ClassName: 'DiskDrive'
         *     condition: selection
         * 3 by Field List：     https://sigmahq.io/docs/basics/rules.html#detection-or
         * detection:
         *     selection:
         *         EventID:
         *             - 4728  # or where
         *             - 4729  # or where
         *             - 4730
         *     condition: selection
         */
        try {
            for (Map.Entry<String, Object> entry : sigmaRuleYaml.getDetection().entrySet()) {
                // detection 名称
                String detectionName = entry.getKey();
                // value 可能是 (List 或者 Map 结构)
                /**
                 * List 结构对应的是 by Keyword 场景
                 */
                Object detectionValue = entry.getValue();

                /**
                 * 一般情况下 detection 下存在 detection 条件字段(如上自定义)、timeframe 字段、fields 字段、condition 字段
                 * 具体参考：https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md
                 * 这里只处理 detection 条件字段 其他暂时过滤
                 */
                if (detectionName.equals("condition") ||
                        detectionName.equals("timeframe") ||
                        detectionName.equals("fields")) {
                    continue;
                }
                detectionManager.addSigmaDetection(
                        detectionName,
                        parseDetection(detectionValue)
                );
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new DetectionErrorException("解析 detection 错误, 请检查文件是否编写正确...");
        }

        return detectionManager;
    }

    @SuppressWarnings("unchecked")
    private SigmaDetection parseDetection(Object value) {
        /**
         * 每个 detection 条件对应一个 SigmaDetection 比如
         * detection:
         *   selection1:
         *     query|contains:
         *       - '.interact.sh'
         *       - '.oast.pro'
         *       - '.oast.live'
         *       - '.oast.site'
         *   selection2:
         *     select: 'tan'
         *   other:
         *     other: 'DNS'
         *   condition: other and (selection1 and selection2)
         * 则对应三个 SigmaDetection
         * selection1 -> SigmaDetection
         * selection2 -> SigmaDetection
         * other      -> SigmaDetection
         */
        SigmaDetection sigmaDetection = new SigmaDetection();

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
    private void parseMap(SigmaDetection sigmaDetection,
                          LinkedHashMap<String, Object> searchMap) {
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
    private void parseList(SigmaDetection sigmaDetection, String filedName, List<Object> searchArray) {
        Detection detection = new Detection();

        /**
         * 字段修饰符格式为：fieldname|mod1|mod2: value 比如如下：
         * 具体参考：https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#value-modifiers
         * detection:
         *     selection:
         *         Provider_Name: 'Application Error'
         *         EventID: 1000
         *         Data|contains|all:
         *             - 'MsMpEng.exe'
         *             - 'mpengine.dll'
         *     condition: selection
         */
        if (filedName != null) {
            parseName(detection, filedName);
        }

        /**
         * List 可能有如下情况
         * 第一种情况：
         * detection:
         *     keywords:
         *         - 'rm *bash_history'
         *         - 'echo "" > *bash_history'
         *         - 'truncate -s0 *bash_history'
         *         - 'history -c'
         *         - 'history -w'
         *     condition: keywords
         * 第二种情况：
         * detection:
         *     selection:
         *         EventID:
         *             - 4728  # or where
         *             - 4729  # or where
         *             - 4730
         *         EventLog: Security
         *     condition: selection
         * 第三种情况 (一般情况下不会出现 而是以 Map 结构出现)：
         * detection:
         *     selection:
         *         - EventID: 4728
         *         - Image: cmd.exe
         *     condition: selection
         */
        for (Object searchValue : searchArray) {
            if ((searchValue instanceof LinkedHashMap)) {
                LinkedHashMap<String, Object> searchMap = (LinkedHashMap<String, Object>) searchValue;
                parseMap(sigmaDetection, searchMap);
            } else {
                parseValue(detection, searchValue.toString());
            }
        }

        if (detection.getValues().size() > 0) {
            sigmaDetection.addDetection(detection);
        }
    }

    private void parseName(Detection detection, String name) {
        String fieldName = StringUtils.substringBefore(name, SEPARATOR);

        detection.setFieldName(fieldName);

        if (name.contains(SEPARATOR)) {
            String[] modifiers = name.split("\\" + SEPARATOR);

            Iterator<String> iterator = Arrays.stream(modifiers).iterator();
            while (iterator.hasNext()) {
                /**
                 * 字段修饰符暂时只考虑 contains、all、endswith、startswith、re 这四种类型
                 * 具体字段修饰符参考：https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#value-modifiers
                 */
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
