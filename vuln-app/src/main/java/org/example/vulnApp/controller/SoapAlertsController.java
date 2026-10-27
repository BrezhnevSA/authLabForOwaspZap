package org.example.vulnApp.controller;

import static org.example.vulnApp.support.ZapAlertVulnSupport.escapeXml;

import java.nio.charset.StandardCharsets;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** SOAP add-on reproductions. Import /vulnApp/soap?wsdl with the ZAP SOAP add-on. */
@RestController
public class SoapAlertsController {

    @RequestMapping(value = "/vulnApp/soap", method = RequestMethod.GET, params = "wsdl")
    public ResponseEntity<String> wsdl(@RequestParam(value = "baseUrl", required = false) String baseUrl) {
        String endpoint = baseUrl == null || baseUrl.isBlank()
            ? "http://localhost:8090/vulnApp/soap"
            : baseUrl + "/vulnApp/soap";
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_XML)
            .body(wsdlBody(endpoint));
    }

    /**
     * Expected via SOAP add-on: 90026 SOAP Action Spoofing and 90029 SOAP XML Injection.
     * The implementation is intentionally wrong: it trusts SOAPAction and lets injected duplicate XML
     * element values influence the response.
     */
    @RequestMapping(value = "/vulnApp/soap", method = RequestMethod.POST, consumes = MediaType.ALL_VALUE)
    public ResponseEntity<String> soap(
        @RequestHeader(value = "SOAPAction", required = false) String soapAction,
        @RequestBody(required = false) byte[] body
    ) {
        String requestBody = body == null ? "" : new String(body, StandardCharsets.UTF_8);
        String action = soapAction == null ? "" : soapAction.replace("\"", "").toLowerCase();
        String userId = lastXmlElementValue(requestBody, "userId");

        if (action.contains("deleteuser")) {
            return soapResponse("deleteUserResponse", "deleted=" + escapeXml(userId));
        }
        return soapResponse("getUserResponse", "user=" + escapeXml(userId));
    }

    private static String lastXmlElementValue(String xml, String tag) {
        String open = "<" + tag + ">";
        String close = "</" + tag + ">";
        int start = xml.lastIndexOf(open);
        int end = xml.lastIndexOf(close);
        if (start >= 0 && end > start) {
            return xml.substring(start + open.length(), end);
        }
        return "42";
    }

    private static ResponseEntity<String> soapResponse(String operation, String value) {
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_XML)
            .body("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                + "<soapenv:Body><" + operation + "><result>" + value + "</result></" + operation + ">"
                + "</soapenv:Body></soapenv:Envelope>");
    }

    private static String wsdlBody(String endpoint) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<definitions name=\"VulnSoapService\" targetNamespace=\"http://example.org/vulnsoap\" "
            + "xmlns=\"http://schemas.xmlsoap.org/wsdl/\" "
            + "xmlns:tns=\"http://example.org/vulnsoap\" "
            + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
            + "xmlns:soap=\"http://schemas.xmlsoap.org/wsdl/soap/\">"
            + "<types><xsd:schema targetNamespace=\"http://example.org/vulnsoap\">"
            + "<xsd:element name=\"getUser\"><xsd:complexType><xsd:sequence>"
            + "<xsd:element name=\"userId\" type=\"xsd:string\"/>"
            + "</xsd:sequence></xsd:complexType></xsd:element>"
            + "<xsd:element name=\"deleteUser\"><xsd:complexType><xsd:sequence>"
            + "<xsd:element name=\"userId\" type=\"xsd:string\"/>"
            + "</xsd:sequence></xsd:complexType></xsd:element>"
            + "</xsd:schema></types>"
            + "<message name=\"getUserRequest\"><part name=\"parameters\" element=\"tns:getUser\"/></message>"
            + "<message name=\"getUserResponse\"><part name=\"parameters\" element=\"tns:getUser\"/></message>"
            + "<message name=\"deleteUserRequest\"><part name=\"parameters\" element=\"tns:deleteUser\"/></message>"
            + "<message name=\"deleteUserResponse\"><part name=\"parameters\" element=\"tns:deleteUser\"/></message>"
            + "<portType name=\"VulnSoapPortType\">"
            + "<operation name=\"getUser\"><input message=\"tns:getUserRequest\"/><output message=\"tns:getUserResponse\"/></operation>"
            + "<operation name=\"deleteUser\"><input message=\"tns:deleteUserRequest\"/><output message=\"tns:deleteUserResponse\"/></operation>"
            + "</portType>"
            + "<binding name=\"VulnSoapBinding\" type=\"tns:VulnSoapPortType\">"
            + "<soap:binding style=\"document\" transport=\"http://schemas.xmlsoap.org/soap/http\"/>"
            + "<operation name=\"getUser\"><soap:operation soapAction=\"getUser\"/>"
            + "<input><soap:body use=\"literal\"/></input><output><soap:body use=\"literal\"/></output></operation>"
            + "<operation name=\"deleteUser\"><soap:operation soapAction=\"deleteUser\"/>"
            + "<input><soap:body use=\"literal\"/></input><output><soap:body use=\"literal\"/></output></operation>"
            + "</binding>"
            + "<service name=\"VulnSoapService\"><port name=\"VulnSoapPort\" binding=\"tns:VulnSoapBinding\">"
            + "<soap:address location=\"" + endpoint + "\"/>"
            + "</port></service></definitions>";
    }
}
