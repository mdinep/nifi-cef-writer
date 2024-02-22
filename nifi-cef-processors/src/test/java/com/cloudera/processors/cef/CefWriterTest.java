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

import org.apache.nifi.util.MockFlowFile;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import org.apache.nifi.util.TestRunner;
import org.apache.nifi.util.TestRunners;

import java.io.ByteArrayInputStream;
import java.util.List;


public class CefWriterTest {
    @After public void tearDown() { }

    private final CefWriter processor = new CefWriter();
    private TestRunner runner;
    private static final boolean VERBOSE = true;

    @Before
    public void init() {
        runner = TestRunners.newTestRunner(CefWriter.class);
    }

    @Test
    public void testSuccessWithMsg()
    {
        System.out.println( "\n--- testSuccess() -----------------------------------------------------------------------" );

// how to set a property value...
        runner.setProperty( processor.CONTENT_AS_MSG, processor.USE_CONTENT_AS_MSG );
        runner.setProperty( processor.SYSLOG_PREFIX, "CEF:1" );
        runner.setProperty( processor.DEVICE_VENDOR, "Security" );
        runner.setProperty( processor.DEVICE_PRODUCT, "threatmanager" );
        runner.setProperty( processor.DEVICE_VERSION, "1.0" );
        runner.setProperty( processor.DEVICE_CLASS_ID, "100" );
        runner.setProperty( processor.EVENT_NAME, "worm successfully stopped" );
        runner.setProperty( processor.EVENT_SEVERITY, "10" );
// how to create flowfile content...
        runner.enqueue( new ByteArrayInputStream( "This is a test file".getBytes() ) );
// this runs the processor; your first breakpoint opportunity is likely onTrigger()...
        runner.run( 1 );
        runner.assertQueueEmpty();

// get all the flowfiles that were transferred to SUCCESS...
        List<MockFlowFile> flowfiles = runner.getFlowFilesForRelationship( processor.SUCCESS );
        assertEquals(1, flowfiles.size() );

// we know there's only one flowfile, so get it for our test...
        MockFlowFile flowfile = flowfiles.get( 0 );  assertNotNull( flowfile );
        String content = new String( runner.getContentAsByteArray( flowfile ) );
        assertEquals("CEF:1|Security|threatmanager|1.0|100|worm successfully stopped|10|msg=This is a test file", content);

        if( VERBOSE )
        {
            System.out.println( "Content: ---------------------------------------------------------------------------------");
            System.out.println( "  " + content );
        }
    }

    @Test
    public void testSuccessNoMsg()
    {
        System.out.println( "\n--- testSuccess() -----------------------------------------------------------------------" );

// set property values...
        runner.setProperty( processor.CONTENT_AS_MSG, processor.DO_NOT_USE_CONTENT_AS_MSG );
        runner.setProperty( processor.SYSLOG_PREFIX, "CEF:1" );
        runner.setProperty( processor.DEVICE_VENDOR, "Security" );
        runner.setProperty( processor.DEVICE_PRODUCT, "threatmanager" );
        runner.setProperty( processor.DEVICE_VERSION, "1.0" );
        runner.setProperty( processor.DEVICE_CLASS_ID, "100" );
        runner.setProperty( processor.EVENT_NAME, "worm successfully stopped" );
        runner.setProperty( processor.EVENT_SEVERITY, "10" );
// create flowfile content...
        runner.enqueue( new ByteArrayInputStream( "This is a test file".getBytes() ) );
// run the processor;
        runner.run( 1 );
        runner.assertQueueEmpty();

// get all the flowfiles that were transferred to SUCCESS...
        List<MockFlowFile> flowfiles = runner.getFlowFilesForRelationship( processor.SUCCESS );
        assertEquals(1, flowfiles.size() );

// we know there's only one flowfile, so get it for our test...
        MockFlowFile flowfile = flowfiles.get( 0 );  assertNotNull( flowfile );
        String content = new String( runner.getContentAsByteArray( flowfile ) );
        assertEquals("CEF:1|Security|threatmanager|1.0|100|worm successfully stopped|10|", content);

        if( VERBOSE )
        {
            System.out.println( "Content: ---------------------------------------------------------------------------------");
            System.out.println( "  " + content );
        }
    }

    @Test
    public void testSuccessWithMsgAndHeader()
    {
        System.out.println( "\n--- testSuccess() -----------------------------------------------------------------------" );

// set property values...
        runner.setProperty( processor.CONTENT_AS_MSG, processor.USE_CONTENT_AS_MSG );
        runner.setProperty( processor.COMPLEX_HEADER, processor.USE_COMPLEX_HEADER );
        runner.setProperty( processor.SYSLOG_PREFIX, "CEF:1" );
        runner.setProperty( processor.DEVICE_VENDOR, "Security" );
        runner.setProperty( processor.DEVICE_PRODUCT, "threatmanager" );
        runner.setProperty( processor.DEVICE_VERSION, "1.0" );
        runner.setProperty( processor.DEVICE_CLASS_ID, "100" );
        runner.setProperty( processor.EVENT_NAME, "worm successfully stopped" );
        runner.setProperty( processor.EVENT_SEVERITY, "10" );
        runner.setProperty( processor.EVENT_DATE, "April 30 08:26:10" );
        runner.setProperty( processor.EVENT_HOST, "host.example.com" );
// create flowfile content...
        runner.enqueue( new ByteArrayInputStream( "This is a test file".getBytes() ) );
// run the processor;
        runner.run( 1 );
        runner.assertQueueEmpty();

// get all the flowfiles that were transferred to SUCCESS...
        List<MockFlowFile> flowfiles = runner.getFlowFilesForRelationship( processor.SUCCESS );
        assertEquals(1, flowfiles.size() );

// we know there's only one flowfile, so get it for our test...
        MockFlowFile flowfile = flowfiles.get( 0 );  assertNotNull( flowfile );
        String content = new String( runner.getContentAsByteArray( flowfile ) );
        assertEquals("April 30 08:26:10 host.example.com CEF:1|Security|threatmanager|1.0|100|worm successfully stopped|10|msg=This is a test file", content);

        if( VERBOSE )
        {
            System.out.println( "Content: ---------------------------------------------------------------------------------");
            System.out.println( "  " + content );
        }
    }

    @Test
    public void testSuccessWithHeader()
    {
        System.out.println( "\n--- testSuccess() -----------------------------------------------------------------------" );

// set property values...
        runner.setProperty( processor.CONTENT_AS_MSG, processor.DO_NOT_USE_CONTENT_AS_MSG );
        runner.setProperty( processor.COMPLEX_HEADER, processor.USE_COMPLEX_HEADER );
        runner.setProperty( processor.SYSLOG_PREFIX, "CEF:1" );
        runner.setProperty( processor.DEVICE_VENDOR, "Security" );
        runner.setProperty( processor.DEVICE_PRODUCT, "threatmanager" );
        runner.setProperty( processor.DEVICE_VERSION, "1.0" );
        runner.setProperty( processor.DEVICE_CLASS_ID, "100" );
        runner.setProperty( processor.EVENT_NAME, "worm successfully stopped" );
        runner.setProperty( processor.EVENT_SEVERITY, "10" );
        runner.setProperty( processor.EVENT_DATE, "April 30 08:26:10" );
        runner.setProperty( processor.EVENT_HOST, "host.example.com" );
// create flowfile content...
        runner.enqueue( new ByteArrayInputStream( "This is a test file".getBytes() ) );
// run the processor;
        runner.run( 1 );
        runner.assertQueueEmpty();

// get all the flowfiles that were transferred to SUCCESS...
        List<MockFlowFile> flowfiles = runner.getFlowFilesForRelationship( processor.SUCCESS );
        assertEquals(1, flowfiles.size() );

// we know there's only one flowfile, so get it for our test...
        MockFlowFile flowfile = flowfiles.get( 0 );  assertNotNull( flowfile );
        String content = new String( runner.getContentAsByteArray( flowfile ) );
        assertEquals("April 30 08:26:10 host.example.com CEF:1|Security|threatmanager|1.0|100|worm successfully stopped|10|", content);

        if( VERBOSE )
        {
            System.out.println( "Content: ---------------------------------------------------------------------------------");
            System.out.println( "  " + content );
        }
    }

    @Test
    public void testSuccessWithDPropsAndHeader()
    {
        System.out.println( "\n--- testSuccess() -----------------------------------------------------------------------" );

// set property values...
        runner.setProperty( processor.CONTENT_AS_MSG, processor.USE_CONTENT_AS_MSG );
        runner.setProperty( processor.COMPLEX_HEADER, processor.USE_COMPLEX_HEADER );
        runner.setProperty( processor.SYSLOG_PREFIX, "CEF:1" );
        runner.setProperty( processor.DEVICE_VENDOR, "Security" );
        runner.setProperty( processor.DEVICE_PRODUCT, "threatmanager" );
        runner.setProperty( processor.DEVICE_VERSION, "1.0" );
        runner.setProperty( processor.DEVICE_CLASS_ID, "100" );
        runner.setProperty( processor.EVENT_NAME, "worm successfully stopped" );
        runner.setProperty( processor.EVENT_SEVERITY, "10" );
        runner.setProperty( processor.EVENT_DATE, "April 30 08:26:10" );
        runner.setProperty( processor.EVENT_HOST, "host.example.com" );
        runner.setProperty( "c6a1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334" );
// create flowfile content...
        runner.enqueue( new ByteArrayInputStream( "This is a test file".getBytes() ) );
// run the processor;
        runner.run( 1 );
        runner.assertQueueEmpty();

// get all the flowfiles that were transferred to SUCCESS...
        List<MockFlowFile> flowfiles = runner.getFlowFilesForRelationship( processor.SUCCESS );
        assertEquals(1, flowfiles.size() );

// we know there's only one flowfile, so get it for our test...
        MockFlowFile flowfile = flowfiles.get( 0 );  assertNotNull( flowfile );
        String content = new String( runner.getContentAsByteArray( flowfile ) );
        assertEquals("April 30 08:26:10 host.example.com CEF:1|Security|threatmanager|1.0|100|worm successfully stopped|10|msg=This is a test file c6a1=2001:0db8:85a3:0000:0000:8a2e:0370:7334", content);

        if( VERBOSE )
        {
            System.out.println( "Content: ---------------------------------------------------------------------------------");
            System.out.println( "  " + content );
        }
    }

    @Test
    public void testSuccessEscapeChars()
    {
        System.out.println( "\n--- testSuccess() -----------------------------------------------------------------------" );

// set property values...
        runner.setProperty( processor.CONTENT_AS_MSG, processor.DO_NOT_USE_CONTENT_AS_MSG );
        runner.setProperty( processor.SYSLOG_PREFIX, "CEF:1" );
        runner.setProperty( processor.DEVICE_VENDOR, "Security\\Policy" );
        runner.setProperty( processor.DEVICE_PRODUCT, "threatmanager|sample" );
        runner.setProperty( processor.DEVICE_VERSION, "1.0" );
        runner.setProperty( processor.DEVICE_CLASS_ID, "100" );
        runner.setProperty( processor.EVENT_NAME, "worm = successfully stopped" );
        runner.setProperty( processor.EVENT_SEVERITY, "10" );
// create flowfile content...
        runner.enqueue( new ByteArrayInputStream( "This is a test file".getBytes() ) );
// run the processor;
        runner.run( 1 );
        runner.assertQueueEmpty();

// get all the flowfiles that were transferred to SUCCESS...
        List<MockFlowFile> flowfiles = runner.getFlowFilesForRelationship( processor.SUCCESS );
        assertEquals(1, flowfiles.size() );

// we know there's only one flowfile, so get it for our test...
        MockFlowFile flowfile = flowfiles.get( 0 );  assertNotNull( flowfile );
        String content = new String( runner.getContentAsByteArray( flowfile ) );
        assertEquals("CEF:1|Security\\\\Policy|threatmanager\\|sample|1.0|100|worm \\= successfully stopped|10|", content);

        if( VERBOSE )
        {
            System.out.println( "Content: ---------------------------------------------------------------------------------");
            System.out.println( "  " + content );
        }
    }

}
