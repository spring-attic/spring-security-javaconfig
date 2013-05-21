/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A base {@link SecurityBuilder} that ensures the object being built is only
 * built one time.
 *
 * @author Rob Winch
 *
 */
public abstract class AbstractSecurityBuilder<T> implements SecurityBuilder<T> {
    private AtomicBoolean building = new AtomicBoolean();

    private T object;

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.SecurityBuilder#build()
     */
    @Override
    public final T build() throws Exception {
        if(building.compareAndSet(false, true)) {
            object = doBuild();
            return object;
        }
        throw new IllegalStateException("This object has already been built");
    }

    public final T getObject() {
        if(building.equals(false)) {
            throw new IllegalStateException("This object has not been built");
        }
        return object;
    }

    final boolean isBuildingOrBuilt() {
        return building.get();
    }

    protected abstract T doBuild() throws Exception;
}
