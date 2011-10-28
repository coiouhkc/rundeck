/*
 * Copyright 2010 DTO Labs, Inc. (http://dtolabs.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.dtolabs.rundeck.jetty.jaas;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.mortbay.jetty.security.Credential;
import org.mortbay.jetty.plus.jaas.spi.UserInfo;

public class JettyCachingHybridLoginModule extends JettyCachingLdapLoginModule {
	
	private PropertyFileLoginModule propfileModule;
	
	public void initialize(Subject subject, CallbackHandler callbackHandler,
            Map sharedState, Map options)
    {
        super.initialize(subject, callbackHandler, sharedState, options);
        propfileModule = new PropertyFileLoginModule();
        propfileModule.initialize(subject, callbackHandler, sharedState, options);
    }
	
	public UserInfo getUserInfo(String username) throws Exception {
        
        String pwdCredential = getUserCredentials(username);

        if (pwdCredential == null) {
            return null;
        }

        pwdCredential = convertCredentialLdapToJetty(pwdCredential);

        Credential credential = Credential.getCredential(pwdCredential);
        //List roles = getUserRoles(_rootContext, username);
        com.dtolabs.rundeck.jetty.jaas.UserInfo localUserInfo = propfileModule.getUserInfo(username);

        return new UserInfo(username, credential, localUserInfo.getRoleNames());
    }
}