/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.pac4j.ext.filter;


import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.web.filter.authc.UserFilter;
import org.apache.shiro.web.util.WebUtils;
import org.pac4j.core.util.Pac4jConstants;

import javax.servlet.ServletRequest;

public class Pac4jUserFilter extends UserFilter {

	@Override
    protected void saveRequest(ServletRequest request) {
        // 还是先执行着shiro自己的方法
        super.saveRequest(request);
        Session session = SecurityUtils.getSubject().getSession();
        session.setAttribute(Pac4jConstants.REQUESTED_URL, WebUtils.toHttp(request).getRequestURI());
    }
	
}

