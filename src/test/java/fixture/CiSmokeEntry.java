package fixture;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class CiSmokeEntry {

    @PostMapping
    public Object handle(String command) throws Exception {
        return Runtime.getRuntime().exec(command);
    }
}
