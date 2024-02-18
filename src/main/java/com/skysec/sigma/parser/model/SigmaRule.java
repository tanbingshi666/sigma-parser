package com.skysec.sigma.parser.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.skysec.sigma.parser.ConditionManager;
import com.skysec.sigma.parser.DetectionManager;
import lombok.Data;

import java.util.List;

/**
 * 解析 sigma rule yaml 文件内容的产物类
 */
@Data
public class SigmaRule {

    // todo 目前解析 sigma rule 只需如下属性即可 后续有其他需求添加即可
    private String title;
    private String description;
    private String id;
    private String author;
    private List<String> references;
    private LogSource logsource;

    private List<String> falsePositives;
    private String level;

    private DetectionManager detectionManager;
    private ConditionManager conditionManager;

    /**
     * 拷贝相关属性
     *
     * @param sigmaRuleYaml sigma rule yaml 文件内容
     */
    public void copySigmaRuleProperties(SigmaRuleYaml sigmaRuleYaml) {
        this.title = sigmaRuleYaml.getTitle();
        this.description = sigmaRuleYaml.getDescription();
        this.id = sigmaRuleYaml.getId();
        this.author = sigmaRuleYaml.getAuthor();
        this.references = sigmaRuleYaml.getReferences();
        this.logsource = sigmaRuleYaml.getLogsource();

        this.falsePositives = sigmaRuleYaml.getFalsepositives();
        this.level = sigmaRuleYaml.getLevel();
    }

    @Override
    public String toString() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return null;
    }

}
