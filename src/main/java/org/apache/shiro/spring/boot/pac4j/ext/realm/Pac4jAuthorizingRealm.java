package org.apache.shiro.spring.boot.pac4j.ext.realm;

import io.buji.pac4j.realm.Pac4jRealm;
import io.buji.pac4j.subject.Pac4jPrincipal;
import io.buji.pac4j.token.Pac4jToken;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.pac4j.core.profile.CommonProfile;

import java.util.Optional;

/**
 *	登录后 Principal 为 Pac4jPrincipal对象,获取传递回来的Profile,
 *	通过:String username = pac4jPrincipal.getProfile().getId();
 * 	如果开启了缓存,应重写权限缓存以及认证缓存的key值,在AuthorizingRealm中的getAuthorizationCacheKey以及getAuthenticationCacheKey,推荐使用username来作为缓存key
 * 
 * @author ： <a href="https://github.com/hiwepy">wandl</a>
 */
@SuppressWarnings("unchecked")
public class Pac4jAuthorizingRealm extends Pac4jRealm {

	@Override
	protected Object getAuthorizationCacheKey(PrincipalCollection principals) {
		Pac4jPrincipal pac4jPrincipal = (Pac4jPrincipal) principals.getPrimaryPrincipal();
		return pac4jPrincipal.getProfile().getId();
	}

	@Override
	protected Object getAuthenticationCacheKey(AuthenticationToken token) {
		if (token instanceof Pac4jToken) {
			Pac4jToken pac4jToken = (Pac4jToken) token;
			Object principal = pac4jToken.getPrincipal();
			if (principal instanceof Optional) {
				Optional<CommonProfile> profileOptional = (Optional<CommonProfile>) principal;
				return profileOptional.get().getId();
			}
		}
		return super.getAuthenticationCacheKey(token);
	}

}
