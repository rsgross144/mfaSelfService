/**
 * 
 */
package multiFactor.saml;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

/**
 * @author epearson
 *
 */
public class BowdUserDetailsService implements SAMLUserDetailsService {

	@Override
	public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
		return new BowdSAMLUserDetails(credential);
	}

}
