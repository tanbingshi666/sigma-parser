import com.skysec.sigma.parser.SigmaRuleParser;
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
        String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\net_dns_external_service_interaction_domains_9.yml";

        SigmaRule sigmaRule = ruleParser.parseRule(Files.readString(Path.of(filename)));
        System.out.println(sigmaRule);

    }

}
