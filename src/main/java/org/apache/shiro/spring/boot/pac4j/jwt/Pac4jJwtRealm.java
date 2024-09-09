package org.apache.shiro.spring.boot.pac4j.jwt;

import io.buji.pac4j.realm.Pac4jRealm;
import io.buji.pac4j.subject.Pac4jPrincipal;
import io.buji.pac4j.token.Pac4jToken;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.pac4j.core.profile.CommonProfile;

import java.util.List;

/**
 * 登录后 Principal 为 Pac4jPrincipal对象,获取cas传递回来的username,
 * 通过:String username = pac4jPrincipal.getProfile().getId();
 * 如果开启了缓存,应重写权限缓存以及认证缓存的key值,在AuthorizingRealm中的getAuthorizationCacheKey以及getAuthenticationCacheKey,推荐使用username来作为缓存key
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class Pac4jJwtRealm extends Pac4jRealm {

	@Override
	protected Object getAuthorizationCacheKey(PrincipalCollection principals) {
		Pac4jPrincipal pac4jPrincipal = (Pac4jPrincipal) principals.getPrimaryPrincipal();
		return pac4jPrincipal.getProfile().getId();
	}

	@Override
	protected Object getAuthenticationCacheKey(AuthenticationToken token) {
		if (token instanceof Pac4jToken) {

			final Pac4jToken pac4jToken = (Pac4jToken) token;
			final List<CommonProfile> profiles = pac4jToken.getProfiles();
			final Pac4jPrincipal principal = new Pac4jPrincipal(profiles);

			return String.valueOf(principal.hashCode());
		}
		return super.getAuthenticationCacheKey(token);
	}

}
