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

import org.apache.nifi.annotation.behavior.*;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.expression.AttributeExpression;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.io.InputStreamCallback;
import org.apache.nifi.processor.io.OutputStreamCallback;
import org.apache.nifi.processor.util.StandardValidators;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@EventDriven
@InputRequirement(InputRequirement.Requirement.INPUT_REQUIRED)
@Tags({"cef", "SIEM", "modification", "update", "Attribute Expression Language", "Arcsight"})
@CapabilityDescription("Builds and outputs a CEF record using configured flowfile attributes or hard-coded values for use by Arcsight and other SIEM applications that utilize the CEF format")
@DynamicProperty(name = "A FlowFile attribute used in the CEF Extension field", value = "The value to set it to", expressionLanguageScope = ExpressionLanguageScope.FLOWFILE_ATTRIBUTES,
        description = "Dynamic Property names and values are used as the key/value of additional CEF fields stored in the CEF Extension field. These names must conform to the CEF schema or user-defined additional custom field names implemented in downstream applications")
@WritesAttribute(attribute = "See additional details", description = "This processor may write or remove zero or more attributes as described in additional details")
public class CefWriter extends AbstractProcessor {

    //Restricted values for dropdown selection of whether complex header will be used
    public static final String DO_NOT_USE_COMPLEX_HEADER = "Do not use complex header";
    public static final String USE_COMPLEX_HEADERE = "Use complex header";
    public static final String USE_CONTENT_AS_MSG = "Use flowfile content";
    public static final String DO_NOT_USE_CONTENT_AS_MSG = "Do not use flowfile content";

    //Complex header selection property
    public static final PropertyDescriptor COMPLEX_HEADER = new PropertyDescriptor.Builder()
            .name("USE_COMPLEX_HEADER")
            .displayName("Use complex header")
            .description("Use the complex header for the first CEF field. This consists of the event date time, event host, and cef version "+
                    "separated by spaces. Setting this to true requires the optional properties 'Event Data' and 'Event Host' to be populated. "+
                    "If these properties are not set, flowfiles will fail to process. NOTE: not all downstream applications are configured to "+
                    "support complex headers in CEF records. Make sure your application can handle this before enabling this option.")
            .required(true)
            .allowableValues(DO_NOT_USE_COMPLEX_HEADER, USE_COMPLEX_HEADERE)
            .defaultValue(DO_NOT_USE_COMPLEX_HEADER)
            .build();

    public static final PropertyDescriptor CONTENT_AS_MSG = new PropertyDescriptor.Builder()
            .name("CONTENT_AS_MSG")
            .displayName("Content as msg")
            .description("Set the content of the flowfile as the value of the 'msg' property in the Extension field of the cef record"+
                    "NOTE: depending on downstream requirements, this could result in a very large record that may not be supported. Use with caution.")
            .required(true)
            .allowableValues(USE_CONTENT_AS_MSG, DO_NOT_USE_CONTENT_AS_MSG)
            .defaultValue(DO_NOT_USE_CONTENT_AS_MSG)
            .build();

    //Required properties for CEF record construction. Supports expression language
    public static final PropertyDescriptor SYSLOG_PREFIX = new PropertyDescriptor
            .Builder().name("SYSLOG_PREFIX")
            .displayName("Syslog Prefix")
            .description("The first field of a CEF object. Example: CEF:1")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            //.addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .addValidator(StandardValidators.createAttributeExpressionLanguageValidator(AttributeExpression.ResultType.STRING, true))
            .build();
    public static final PropertyDescriptor DEVICE_VENDOR = new PropertyDescriptor
            .Builder().name("DEVICE_VENDOR")
            .displayName("Device Vendor")
            .description("The second field of a CEF object. Example: Security")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .addValidator(StandardValidators.createAttributeExpressionLanguageValidator(AttributeExpression.ResultType.STRING, true))
            .build();
    public static final PropertyDescriptor DEVICE_PRODUCT = new PropertyDescriptor
            .Builder().name("DEVICE_PRODUCT")
            .displayName("Device Product")
            .description("The third field of a CEF object. Example: threatmanager")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .addValidator(StandardValidators.createAttributeExpressionLanguageValidator(AttributeExpression.ResultType.STRING, true))
            .build();
    public static final PropertyDescriptor DEVICE_VERSION = new PropertyDescriptor
            .Builder().name("DEVICE_VERSION")
            .displayName("Device Version")
            .description("The fourth field of a CEF object. Example: 1.0")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .addValidator(StandardValidators.createAttributeExpressionLanguageValidator(AttributeExpression.ResultType.STRING, true))
            .build();
    public static final PropertyDescriptor DEVICE_CLASS_ID = new PropertyDescriptor
            .Builder().name("DEVICE_CLASS_ID")
            .displayName("Device Event Class ID")
            .description("The fifth field of a CEF object. Example: 100")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .addValidator(StandardValidators.createAttributeExpressionLanguageValidator(AttributeExpression.ResultType.STRING, true))
            .build();
    public static final PropertyDescriptor EVENT_NAME = new PropertyDescriptor
            .Builder().name("EVENT_NAME")
            .displayName("Event Name")
            .description("The sixth field of a CEF object. Example: worm successfully stopped")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .addValidator(StandardValidators.createAttributeExpressionLanguageValidator(AttributeExpression.ResultType.STRING, true))
            .build();
    public static final PropertyDescriptor EVENT_SEVERITY = new PropertyDescriptor
            .Builder().name("EVENT_SEVERITY")
            .displayName("Event Severity")
            .description("The seventh field of a CEF object. Example: 10")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .addValidator(StandardValidators.createAttributeExpressionLanguageValidator(AttributeExpression.ResultType.STRING, true))
            .build();

    //Optional properties for CEF records. Required if complex header is set to true
    public static final PropertyDescriptor EVENT_DATE = new PropertyDescriptor
            .Builder().name("EVENT_DATE")
            .displayName("Event DateTime")
            .description("Optional datetime value that can be part of the Header. Example: Sept 29 08:26:10")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .addValidator(StandardValidators.createAttributeExpressionLanguageValidator(AttributeExpression.ResultType.STRING, true))
            .build();
    public static final PropertyDescriptor EVENT_HOST = new PropertyDescriptor
            .Builder().name("EVENT_HOST")
            .displayName("Event Host")
            .description("Optional hostname value that can be part of the Header. Example: host.example.com")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .addValidator(StandardValidators.createAttributeExpressionLanguageValidator(AttributeExpression.ResultType.STRING, true))
            .build();


    //Codeblock for processor to support dynamic properties. Used to build key/value pairs for CEF extension field
    @Override
    protected PropertyDescriptor getSupportedDynamicPropertyDescriptor(final String propertyDescriptorName) {
        return new PropertyDescriptor.Builder()
                .name(propertyDescriptorName)
                .required(false)
                .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
                .addValidator(StandardValidators.ATTRIBUTE_KEY_PROPERTY_NAME_VALIDATOR)
                .addValidator(StandardValidators.createAttributeExpressionLanguageValidator(AttributeExpression.ResultType.STRING, true))
                .dynamic(true)
                .build();
    }



    //Relationships to which flowfiles are transferred
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

    @Override
    protected void init(final ProcessorInitializationContext context) {
        properties = new ArrayList<>();
        properties.add(COMPLEX_HEADER);
        properties.add(CONTENT_AS_MSG);
        properties.add(SYSLOG_PREFIX);
        properties.add(DEVICE_VENDOR);
        properties.add(DEVICE_PRODUCT);
        properties.add(DEVICE_VERSION);
        properties.add(DEVICE_CLASS_ID);
        properties.add(EVENT_NAME);
        properties.add(EVENT_SEVERITY);
        properties.add(EVENT_DATE);
        properties.add(EVENT_HOST);

        properties = Collections.unmodifiableList(properties);

        relationships = new HashSet<>();
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

    //Method to check and fix dat formatting for CEF records. Ensures that unallowed control characters are properly escaped
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

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) {
        FlowFile flowFile = session.get();
        if (flowFile == null) {
            return;
        }

        StringJoiner cefJ = new StringJoiner("|");
        StringJoiner fieldJ = new StringJoiner(" ");
        String cefPref = context.getProperty(SYSLOG_PREFIX).evaluateAttributeExpressions(flowFile).getValue();
        String complexHeader = context.getProperty(COMPLEX_HEADER).evaluateAttributeExpressions(flowFile).getValue();
        String contentMsg = context.getProperty(CONTENT_AS_MSG).evaluateAttributeExpressions(flowFile).getValue();

        if(complexHeader.equals(USE_COMPLEX_HEADERE)) {
            String datetime = context.getProperty(EVENT_DATE).evaluateAttributeExpressions(flowFile).getValue();
            String eventHost = context.getProperty(EVENT_HOST).evaluateAttributeExpressions(flowFile).getValue();

            String headerString = new StringJoiner(" ").add(datetime).add(eventHost).add(cefPref).toString();
            try{
                cefJ.add(formatText(headerString));
            } catch (Exception ex){
                ex.printStackTrace();
                getLogger().error("Failed to Build complex CEF header.");
                session.transfer(flowFile, FAILURE);
            }

        } else {
            try{
                cefJ.add(formatText(cefPref));
            }catch (Exception ex){
                ex.printStackTrace();
                getLogger().error("Failed to write simple CEF header.");
                session.transfer(flowFile, FAILURE);
            }
        }

        try{
            cefJ.add(formatText(context.getProperty(DEVICE_VENDOR).evaluateAttributeExpressions(flowFile).getValue()));
            cefJ.add(formatText(context.getProperty(DEVICE_PRODUCT).evaluateAttributeExpressions(flowFile).getValue()));
            cefJ.add(formatText(context.getProperty(DEVICE_VERSION).evaluateAttributeExpressions(flowFile).getValue()));
            cefJ.add(formatText(context.getProperty(DEVICE_CLASS_ID).evaluateAttributeExpressions(flowFile).getValue()));
            cefJ.add(formatText(context.getProperty(EVENT_NAME).evaluateAttributeExpressions(flowFile).getValue()));
            cefJ.add(formatText(context.getProperty(EVENT_SEVERITY).evaluateAttributeExpressions(flowFile).getValue()));

        }catch (Exception ex){
            ex.printStackTrace();
            getLogger().error("Failed to add field to CEF record. Check to make sure all required fields have valid values.");
            session.transfer(flowFile, FAILURE);
        }

        if(contentMsg.equals(USE_CONTENT_AS_MSG)){
            session.read(flowFile, new InputStreamCallback() {
                @Override
                public void process(InputStream inputStream) {
                    try {
                        String text = new BufferedReader(
                                new InputStreamReader(inputStream, StandardCharsets.UTF_8))
                                .lines()
                                .collect(Collectors.joining(" "));
                        fieldJ.add("msg=" + formatText(text));
                    } catch (Exception ex) {
                        ex.printStackTrace();
                        getLogger().error("Failed to read flowfile content.");
                        session.transfer(flowFile, FAILURE);
                    }
                }
            });
        }

        for ( Map.Entry< PropertyDescriptor, String > entry : context.getProperties().entrySet() ){
            PropertyDescriptor dynamicProps = entry.getKey();
            if(dynamicProps.isDynamic()) {
                final String PROPERTY_NAME  = dynamicProps.getName();
                final String PROPERTY_VALUE = formatText(context.getProperty(PROPERTY_NAME).evaluateAttributeExpressions(flowFile).getValue());
                fieldJ.add(PROPERTY_NAME.strip() + "=" +PROPERTY_VALUE.strip());
            }
        }
        cefJ.add(fieldJ.toString());
        FlowFile cefF = session.create(flowFile);
        cefF = session.write(cefF, new OutputStreamCallback() {
            @Override
            public void process(OutputStream outputStream) throws IOException {
                try{
                    outputStream.write(cefJ.toString().getBytes());
                }catch(Exception ex){
                    ex.printStackTrace();
                    getLogger().error("Failed to write CEF record to new flowfile content.");
                    session.transfer(flowFile, FAILURE);
                }
            }
        });

        session.remove(flowFile);
        session.transfer(cefF, SUCCESS);
    }
}
