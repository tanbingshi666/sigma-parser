import com.fasterxml.jackson.core.JsonProcessingException;
import com.skysec.sigma.parser.SigmaRuleParser;
import com.skysec.sigma.parser.exception.ConditionErrorException;
import com.skysec.sigma.parser.exception.DetectionErrorException;
import com.skysec.sigma.parser.model.SigmaRule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class TestSigmaRuleParser {

    public static void main(String[] args) throws IOException {
        SigmaRuleParser ruleParser = new SigmaRuleParser();

        // todo 测试解析 detection 内容
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\net_dns_external_service_interaction_domains.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\net_dns_external_service_interaction_domains_2.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\net_dns_external_service_interaction_domains_3.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\net_dns_external_service_interaction_domains_4.yml";

        // todo 测试解析 condition 内容
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\condition\\net_dns_external_service_interaction_domains.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\condition\\net_dns_external_service_interaction_domains_2.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\condition\\net_dns_external_service_interaction_domains_3.yml";

        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\net_dns_external_service_interaction_domains_5.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\net_dns_external_service_interaction_domains_6.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\net_dns_external_service_interaction_domains_7.yml";

        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\net_dns_external_service_interaction_domains_8.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\net_dns_external_service_interaction_domains_9.yml";

        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\net_dns_external_service_interaction_domains_10.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\net_dns_external_service_interaction_domains_11.yml";

        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\dev\\win_av_relevant_match.yml";
        String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\dev\\win_av_relevant_match2.yml";

        SigmaRule sigmaRule = null;
        try {
            sigmaRule = ruleParser.parseRule(Files.readString(Path.of(filename)));
        } catch (DetectionErrorException e1) {
            System.out.println("解析 detection 出错, 请检查是否编写正确...");
            e1.printStackTrace();
        } catch (ConditionErrorException e2) {
            System.out.println("解析 condition 出错, 请检查是否编写正确...");
            e2.printStackTrace();
        } catch (JsonProcessingException e3) {
            e3.printStackTrace();
            System.out.println("解析规则文件出错, 请检查是否编写正确...");
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(sigmaRule);

    }

}
