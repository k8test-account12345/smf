// ProtocolConfigurationOptions
package context

type ProtocolConfigurationOptions struct {
	DNSIPv4Request     bool
	DNSIPv6Request     bool
	PCSCFIPv4Request   bool
	IPv4LinkMTURequest bool
	// IPCPRequest is set when the UE asks for DNS via the legacy IPCP (0x8021)
	// protocol container instead of (or in addition to) the 0x000d container.
	IPCPRequest bool
	// IPCPIdentifier echoes the Identifier byte from the UE's IPCP Configure-Request.
	IPCPIdentifier uint8
}
