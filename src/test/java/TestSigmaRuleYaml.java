import cn.hutool.core.io.file.FileReader;
import cn.hutool.json.JSONObject;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.skysec.sigma.parser.ConditionManager;
import com.skysec.sigma.parser.SigmaRuleParser;
import com.skysec.sigma.parser.model.SigmaRule;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TestSigmaRuleYaml {

    public static final Map<String, String> rules = new HashMap<>();
    public static long count = 0L;

    public static long parseDetectionSuccess = 0L;
    public static Map<String, String> parseDetectionError = new HashMap<>();

    public static Map<String, SigmaRule> sigmaRules = new HashMap<>();

    public static void main(String[] args) throws JsonProcessingException {

        /**
         * 需求：验证目前的 sigma parser 是否完成覆盖 github sigma rule
         */

        // 读取 sigma rule 文件内容
        String path = "D:\\project\\tianax\\sigma-parser\\rules";
        File file = new File(path);
        func(file);

        // sigma rule 文件总数为 2878
        System.out.println("sigma rule 文件总数为 " + count);

        for (Map.Entry<String, String> entry : rules.entrySet()) {
            SigmaRuleParser ruleParser = new SigmaRuleParser();
            try {
                SigmaRule sigmaRule = ruleParser.parseRule(entry.getValue());
                sigmaRules.put(entry.getKey(), sigmaRule);
                parseDetectionSuccess++;
            } catch (Exception e) {
                parseDetectionError.put(entry.getKey(), entry.getValue());
            }
        }

        // 成功解析 sigma rule detection 个数 2878
        System.out.println("成功解析 sigma rule detection 个数 " + parseDetectionSuccess);
        // 失败解析 sigma rule detection 个数 0
        System.out.println("失败解析 sigma rule detection 个数 " + parseDetectionError.size());
        for (Map.Entry<String, String> entry : parseDetectionError.entrySet()) {
            System.out.println(entry.getKey());
        }
        JSONObject json = new JSONObject();
        json.set("keywords", "Adfind");
        json.set("Level", 4);
        json.set("Name", "sigma");
        json.set("Image", "bbb\\AppData\\Local\\Keybase\\upd.exe");
        json.set("Status", "Success");

        // String message = "{\"query\": [\".interact.sh\",\"aaa\"],\"select\": \"tan\"}";
        ObjectMapper mapper = new ObjectMapper();
        JsonNode valueJson = mapper.readTree(json.toJSONString(0));

        for (Map.Entry<String, SigmaRule> entry : sigmaRules.entrySet()) {
            ConditionManager conditionManager = entry.getValue().getConditionManager();
            if (conditionManager != null) {
                boolean parse = false;
                try {
                    parse = conditionManager.parse(entry.getValue().getDetectionManager().getSigmaDetections(), valueJson);
                    if (parse) {
                        System.out.println("测试数据匹配成功: " + entry.getKey());
                    }
                } catch (Exception e) {
                    System.out.println("解析错误: " + entry.getKey());
                    e.printStackTrace();
                }
            }
        }

    }

    private static void func(File file) {
        File[] fs = file.listFiles();
        if (fs == null) {
            return;
        }
        for (File f : fs) {
            if (f.isDirectory())
                func(f);
            if (f.isFile()) {
                if (f.getAbsolutePath().endsWith(".yml") || f.getAbsolutePath().endsWith(".yaml")) {
                    count++;
                }
                String content = FileReader.create(f).readString();
                rules.put(f.getAbsolutePath(), content);
            }
        }
    }

}
