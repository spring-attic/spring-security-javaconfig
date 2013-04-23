/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.web.util;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.MediaType;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.context.request.ServletWebRequest;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
public class MediaTypeRequestMatcher implements RequestMatcher {
    private ContentNegotiationStrategy contentNegotiationStrategy;
    private MediaType matchingMediaType;

    public MediaTypeRequestMatcher(ContentNegotiationStrategy contentNegotiationStrategy, MediaType mediaType) {
        this.contentNegotiationStrategy = contentNegotiationStrategy;
        this.matchingMediaType = mediaType;
    }

    public boolean matches(HttpServletRequest request) {
        List<MediaType> mediaTypes;
        try {
            mediaTypes = contentNegotiationStrategy.resolveMediaTypes(new ServletWebRequest(request));
        }
        catch (HttpMediaTypeNotAcceptableException e) {
            throw new RuntimeException(e);
        }
        for(MediaType mediaType : mediaTypes) {
            if(mediaType.includes(matchingMediaType)) {
                return true;
            }
        }
        return false;
    }

}
