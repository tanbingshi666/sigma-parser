import java.util.Arrays;

public class Test {
    public static void main(String[] args) {

        String s = "query|container";
        String[] split = s.split("\\|");
        System.out.println(Arrays.toString(split));

    }
}
