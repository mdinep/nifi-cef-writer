/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.cloudera.processors.cef;

import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.expression.AttributeExpression;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.util.StandardValidators;

import java.util.*;

@Tags({"example"})
@CapabilityDescription("Provide a description")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
public class CefWriter extends AbstractProcessor {

    public static final PropertyDescriptor SYSLOG_PREFIX = new PropertyDescriptor
            .Builder().name("SYSLOG_PREFIX")
            .displayName("Syslog Prefix")
            .description("The first field of a CEF object. Example: CEF:1")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor DEVICE_VENDOR = new PropertyDescriptor
            .Builder().name("DEVICE_VENDOR")
            .displayName("Device Vendor")
            .description("The second field of a CEF object. Example: Security")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor DEVICE_PRODUCT = new PropertyDescriptor
            .Builder().name("DEVICE_PRODUCT")
            .displayName("Device Product")
            .description("The third field of a CEF object. Example: threatmanager")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor DEVICE_VERSION = new PropertyDescriptor
            .Builder().name("DEVICE_VERSION")
            .displayName("Device Version")
            .description("The fourth field of a CEF object. Example: 1.0")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor DEVICE_CLASS_ID = new PropertyDescriptor
            .Builder().name("DEVICE_CLASS_ID")
            .displayName("Device Event Class ID")
            .description("The fifth field of a CEF object. Example: 100")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor EVENT_NAME = new PropertyDescriptor
            .Builder().name("EVENT_NAME")
            .displayName("Event Name")
            .description("The sixth field of a CEF object. Example: worm successfully stopped")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor EVENT_SEVERITY = new PropertyDescriptor
            .Builder().name("EVENT_SEVERITY")
            .displayName("Event Severity")
            .description("The seventh field of a CEF object. Example: 10")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor EVENT_DATE = new PropertyDescriptor
            .Builder().name("EVENT_DATE")
            .displayName("Event DateTime")
            .description("Optional datetime value that can be part of the Header. Example: Sept 29 08:26:10")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor EVENT_HOST = new PropertyDescriptor
            .Builder().name("EVENT_HOST")
            .displayName("Event Host")
            .description("Optional hostname value that can be part of the Header. Example: host.example.com")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();


    public static final Relationship ORIGINAL = new Relationship.Builder()
            .name("Original")
            .description("The original input flowfile")
            .build();
    public static final Relationship SUCCESS = new Relationship.Builder()
            .name("Success")
            .description("The flowfile has been successfully processed to CEF")
            .build();

    public static final Relationship FAILURE = new Relationship.Builder()
            .name("Failure")
            .description("The flowfile has failed to be processed to CEF successfully")
            .build();

    private List<PropertyDescriptor> properties;
    private Set<Relationship> relationships;
    private volatile boolean stateful = false;

    @Override
    protected void init(final ProcessorInitializationContext context) {
        properties = new ArrayList<>();
        properties.add(SYSLOG_PREFIX);
        properties.add(DEVICE_VENDOR);
        properties.add(DEVICE_PRODUCT);
        properties.add(DEVICE_VERSION);
        properties.add(DEVICE_CLASS_ID);
        properties.add(EVENT_SEVERITY);
        properties.add(EVENT_DATE);
        properties.add(EVENT_HOST);

        properties = Collections.unmodifiableList(properties);

        relationships = new HashSet<>();
        relationships.add(ORIGINAL);
        relationships.add(SUCCESS);
        relationships.add(FAILURE);
        relationships = Collections.unmodifiableSet(relationships);
    }

    @Override
    public Set<Relationship> getRelationships() {
        return this.relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return properties;
    }

    /*
    @Override
    protected PropertyDescriptor getSupportedDynamicPropertyDescriptor(final String propertyDescriptorName) {
        PropertyDescriptor.Builder propertyBuilder = new PropertyDescriptor.Builder()
                .name(propertyDescriptorName)
                .required(false)
                .addValidator(StandardValidators.ATTRIBUTE_KEY_PROPERTY_NAME_VALIDATOR)
                .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
                .dynamic(true);

        if (stateful) {
            return propertyBuilder
                    .addValidator(StandardValidators.createAttributeExpressionLanguageValidator(AttributeExpression.ResultType.STRING, true))
                    .build();
        } else {
            return propertyBuilder
                    .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
                    .build();
        }
    }
    */

    public final String formatText(String inputString){
        StringBuilder outputString = new StringBuilder();
        for(int i=0;i < inputString.length();i++){
            if (String.valueOf(inputString.charAt(i)).equals("=") || String.valueOf(inputString.charAt(i)).equals("|")){
                outputString.append("\\").append(inputString.charAt(i));
            } else if (String.valueOf(inputString.charAt(i)).equals("\\")
                    && !String.valueOf(inputString.charAt(i-1)).equals("\\")
                    && !String.valueOf(inputString.charAt(i+1)).equals("\\")){
                outputString.append("\\").append(inputString.charAt(i));
            } else {
                outputString.append(inputString.charAt(i));
            }
        }
        return outputString.toString();
    }

    @OnScheduled
    public void onScheduled(final ProcessContext context) {

    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) {
        FlowFile flowFile = session.get();
        if (flowFile == null) {
            return;
        }
        // TODO implement
    }
}
