/**
 * 
 */
package multiFactor.saml;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml.SAMLCredential;

import com.github.ulisesbocchio.spring.boot.security.saml.user.SAMLUserDetails;

/**
 * @author epearson
 *
 */
public class BowdSAMLUserDetails extends SAMLUserDetails {

	private static final long serialVersionUID = 1L;
	
	private final SAMLCredential bowdSamlCredential;

	public BowdSAMLUserDetails(SAMLCredential samlCredential) {
		super(samlCredential);
		this.bowdSamlCredential = samlCredential;
	}
	
	@Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
		List<SimpleGrantedAuthority> authorities = new ArrayList<>();
		
		authorities.add(new SimpleGrantedAuthority("ROLE_USER")); // making sure they get at least one authority
		
		// roles: http://schemas.microsoft.com/ws/2008/06/identity/claims/role
		String[] roles = bowdSamlCredential.getAttributeAsStringArray("http://schemas.microsoft.com/ws/2008/06/identity/claims/role");
		
		if (roles != null) {
			for (String role: roles) {
				authorities.add(new SimpleGrantedAuthority(role));
			}
		}
		
        return authorities;
    }

}
