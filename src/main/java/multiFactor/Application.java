package multiFactor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import com.github.ulisesbocchio.spring.boot.security.saml.annotation.EnableSAMLSSO;

@SpringBootApplication
@EnableSAMLSSO
public class Application {

    public static void main(String[] args) throws Throwable {
        SpringApplication.run(Application.class, args);
    }

}
