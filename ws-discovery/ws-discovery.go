package wsdiscovery

import (
	"strings"

	"github.com/IOTechSystems/onvif/gosoap"
	"github.com/beevik/etree"
)

// BuildProbeMessage generates a SOAP ws-discovery Probe message
//
// Example Message:
//<?xml version="1.0" encoding="UTF-8"?>
//<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
//  <Header>
//    <a:Action mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
//    <a:MessageID>uuid:78a2ed98-bc1f-4b08-9668-094fcba81e35</a:MessageID>
//    <a:ReplyTo>
//      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
//    </a:ReplyTo>
//    <a:To mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
//  </Header>
//  <Body>
//    <Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
//      <d:Types xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dp0="http://www.onvif.org/ver10/network/wsdl">dp0:NetworkVideoTransmitter</d:Types>
//    </Probe>
//  </Body>
//</Envelope>
func BuildProbeMessage(uuidV4 string, scopes, types []string, nmsp map[string]string) gosoap.SoapMessage {
	// Namespace List
	namespaces := make(map[string]string)
	namespaces["a"] = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
	//namespaces["d"] = "http://schemas.xmlsoap.org/ws/2005/04/discovery"

	probeMessage := gosoap.NewEmptySOAP()

	probeMessage.AddRootNamespaces(namespaces)
	//if len(nmsp) != 0 {
	//	probeMessage.AddRootNamespaces(nmsp)
	//}

	//fmt.Println(probeMessage.String())

	// Header Content
	var headerContent []*etree.Element

	action := etree.NewElement("a:Action")
	action.SetText("http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe")
	action.CreateAttr("mustUnderstand", "1")

	msgID := etree.NewElement("a:MessageID")
	msgID.SetText("uuid:" + uuidV4)

	replyTo := etree.NewElement("a:ReplyTo")
	replyTo.CreateElement("a:Address").SetText("http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous")

	to := etree.NewElement("a:To")
	to.SetText("urn:schemas-xmlsoap-org:ws:2005:04:discovery")
	to.CreateAttr("mustUnderstand", "1")

	headerContent = append(headerContent, action, msgID, replyTo, to)
	probeMessage.AddHeaderContents(headerContent)

	// Body Content
	probe := etree.NewElement("Probe")
	probe.CreateAttr("xmlns", "http://schemas.xmlsoap.org/ws/2005/04/discovery")

	if len(types) != 0 {
		typesTag := etree.NewElement("d:Types")
		if len(nmsp) != 0 {
			for key, value := range nmsp {
				typesTag.CreateAttr("xmlns:"+key, value)
			}
		}
		typesTag.CreateAttr("xmlns:d", "http://schemas.xmlsoap.org/ws/2005/04/discovery")
		//typesTag.CreateAttr("xmlns:dp0", "http://www.onvif.org/ver10/network/wsdl")
		var typesString string
		for _, j := range types {
			typesString += j
			typesString += " "
		}

		typesTag.SetText(strings.TrimSpace(typesString))

		probe.AddChild(typesTag)
	}

	if len(scopes) != 0 {
		scopesTag := etree.NewElement("d:Scopes")
		var scopesString string
		for _, j := range scopes {
			scopesString += j
			scopesString += " "
		}
		scopesTag.SetText(strings.TrimSpace(scopesString))

		probe.AddChild(scopesTag)
	}

	probeMessage.AddBodyContent(probe)

	return probeMessage
}
