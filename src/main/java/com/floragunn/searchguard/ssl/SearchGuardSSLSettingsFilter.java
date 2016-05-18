/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.ssl;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.SettingsFilter;

import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

public class SearchGuardSSLSettingsFilter {

    private static final Pattern FILTER_PATTERN = Pattern.compile("searchguard.ssl.*");

    @Inject
    public SearchGuardSSLSettingsFilter(final SettingsFilter settingsFilter) {
        super();
        settingsFilter.addFilter(new SettingsFilter.Filter() {
            @Override
            public void filter(ImmutableSettings.Builder settings) {
                Iterator<Map.Entry<String, String>> iterator = settings.internalMap().entrySet().iterator();
                while (iterator.hasNext()) {
                    if (FILTER_PATTERN.matcher(iterator.next().getKey()).matches()) {
                        iterator.remove();
                    }
                }
            }
        });
    }
}
