package io.just.sast.frontend.asm;

import io.just.sast.model.ApplicationResourceFacts;
import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract tests for bounded deployment-resource parsing and route correlation. */
class ApplicationResourceParserTest {

    @Test
    void correlatesHandlerRouteAndServletDeploymentWithoutExecutingTargetCode() {
        ApplicationResourceParser.Collector collector =
                new ApplicationResourceParser.Collector(InputBudget.defaults());
        collector.accept("WEB-INF/handlers-controller.xml", bytes(
                "<handlers><handler name=\"soap\" type=\"request\" "
                        + "class=\"org.apache.ofbiz.webapp.event.SOAPEventHandler\"/>"
                        + "</handlers>"));
        collector.accept("WEB-INF/controller.xml", bytes(
                "<site><request-map uri=\"SOAPService\"><event type=\"soap\"/>"
                        + "</request-map></site>"));
        collector.accept("WEB-INF/web.xml", bytes(
                "<web-app><servlet><servlet-name>control</servlet-name>"
                        + "<servlet-class>org.apache.ofbiz.webapp.control.ControlServlet</servlet-class>"
                        + "</servlet><servlet-mapping><servlet-name>control</servlet-name>"
                        + "<url-pattern>/control/*</url-pattern></servlet-mapping></web-app>"));

        ApplicationResourceFacts facts = collector.finish();

        assertEquals(1, facts.routeBindings().size());
        ApplicationResourceFacts.RouteBinding route = facts.routeBindings().get(0);
        assertEquals("SOAPService", route.route());
        assertEquals("request", route.handlerType());
        assertEquals("org/apache/ofbiz/webapp/event/SOAPEventHandler", route.handlerClass());
        assertEquals("invoke", route.handlerMethod());
        assertEquals("org/apache/ofbiz/webapp/control/ControlServlet", route.servletClass());
        assertEquals("/control/*", route.servletPattern());
        assertTrue(route.externalControlProven());
        assertTrue(facts.completenessReasons().isEmpty());
    }

    @Test
    void rejectsDoctypeAndIgnoresUnrelatedXml() {
        ApplicationResourceParser.Collector collector =
                new ApplicationResourceParser.Collector(InputBudget.defaults());
        collector.accept("META-INF/ordinary.xml", bytes("<root><value>ignored</value></root>"));
        collector.accept("WEB-INF/controller.xml", bytes(
                "<!DOCTYPE request-map [<!ENTITY x SYSTEM \"file:///secret\">]>"
                        + "<request-map uri=\"SOAPService\"><event type=\"soap\"/></request-map>"));

        ApplicationResourceFacts facts = collector.finish();

        assertTrue(facts.routeBindings().isEmpty());
        assertEquals(1, facts.completenessReasons().size());
        assertTrue(facts.completenessReasons().get(0).startsWith(
                "APPLICATION_RESOURCE_PARSE_FAILED:WEB-INF/controller.xml"));
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
