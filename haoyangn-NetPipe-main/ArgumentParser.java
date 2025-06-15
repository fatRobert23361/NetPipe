import java.util.Map;

public class ArgumentParser {
    public static Arguments parse(String[] args, Map<String, String> specs) {
        Arguments arguments = new Arguments();
        for (Map.Entry<String, String> entry : specs.entrySet()) {
            arguments.setArgumentSpec(entry.getKey(), entry.getValue());
        }
        arguments.loadArguments(args);
        return arguments;
    }
}