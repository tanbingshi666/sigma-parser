package com.skysec.sigma.parser;

import cn.hutool.log.Log;
import cn.hutool.log.dialect.console.ConsoleLog;
import com.skysec.sigma.parser.model.SigmaDetection;

import java.util.HashMap;
import java.util.Map;

/**
 * sigma detection 管理器
 * 一般情况下一个 yaml 文件对应的 detection 对应一个 DetectionsManager 类
 * 同时一个 SigmaDetection 可能缓存 N 个 Detection 因为一个 yaml 文件内容可能多个 detection 条件 如下:
 * detection:
 *     selection:
 *         dst_port:
 *             - 8080
 *     selection_allow1:
 *         action:
 *             - forward
 *     selection_allow2:
 *         blocked: "false"
 *     selection_allow3:
 *         - query|containers: "http"
 *         - sql|containers: "select"  -- 可以另起一个 selection_allow
 *     condition: selection and 1 of selection_allow*
 */
public class DetectionManager {

    private final Log console = new ConsoleLog(DetectionManager.class);

    private final Map<String, SigmaDetection> sigmaDetections = new HashMap<>();

    public void addSigmaDetection(String detectionName, SigmaDetection sigmaDetection) {
        sigmaDetections.put(detectionName, sigmaDetection);
    }

    public SigmaDetection getSigmaDetectionByName(String detectionName) {
        return sigmaDetections.get(detectionName);
    }

    public Map<String, SigmaDetection> getSigmaDetections() {
        return sigmaDetections;
    }

}
