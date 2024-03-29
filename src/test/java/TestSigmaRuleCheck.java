import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.skysec.sigma.parser.SigmaRuleParser;
import com.skysec.sigma.parser.model.SigmaRule;
import com.skysec.sigma.parser.utils.SigmaRuleUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class TestSigmaRuleCheck {
    public static void main(String[] args) throws IOException {

        SigmaRuleParser ruleParser = new SigmaRuleParser();

        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains_2.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains_3.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains_4.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains_5.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains_6.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains_7.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains_8.yml";

        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains_9.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains_10.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains_11.yml";

        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains_12.yml";
        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains_13.yml";

        // String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains_14.yml";
        String filename = "D:\\project\\tianax\\sigma-parser\\yaml\\check\\net_dns_external_service_interaction_domains_15.yml";

        SigmaRule sigmaRule = ruleParser.parseRule(Files.readString(Path.of(filename)));

        String message = "{\"query\": \"22.interact.sh\",\"select\": \"tan11\",\"other\": \"DNS\"}";
        //String message = "{\"query\": [\".interact.sh\",\"aaa\"],\"select\": \"tan\"}";

        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readTree(message);

        SigmaRuleUtils sigmaRuleCheck = new SigmaRuleUtils();
        Boolean valid = sigmaRuleCheck.isValid(sigmaRule, jsonNode);
        System.out.println(valid);

    }
}
