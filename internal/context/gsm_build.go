package context

import (
	"net"
	"encoding/hex"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasConvert"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/smf/internal/logger"
)

func BuildGSMPDUSessionEstablishmentAccept(smContext *SMContext) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionEstablishmentAccept)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionEstablishmentAccept = nasMessage.NewPDUSessionEstablishmentAccept(0x0)
	pDUSessionEstablishmentAccept := m.PDUSessionEstablishmentAccept

	sessRule := smContext.SelectedSessionRule()
	authDefQos := sessRule.AuthDefQos

	pDUSessionEstablishmentAccept.SetPDUSessionID(uint8(smContext.PDUSessionID))
	pDUSessionEstablishmentAccept.SetMessageType(nas.MsgTypePDUSessionEstablishmentAccept)
	pDUSessionEstablishmentAccept.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pDUSessionEstablishmentAccept.SetPTI(smContext.Pti)

	if v := smContext.EstAcceptCause5gSMValue; v != 0 {
		pDUSessionEstablishmentAccept.Cause5GSM = nasType.NewCause5GSM(nasMessage.PDUSessionEstablishmentAcceptCause5GSMType)
		pDUSessionEstablishmentAccept.Cause5GSM.SetCauseValue(v)
	}
	pDUSessionEstablishmentAccept.SetPDUSessionType(smContext.SelectedPDUSessionType)

	pDUSessionEstablishmentAccept.SetSSCMode(1)
	pDUSessionEstablishmentAccept.SessionAMBR = nasConvert.ModelsToSessionAMBR(sessRule.AuthSessAmbr)
	pDUSessionEstablishmentAccept.SessionAMBR.SetLen(uint8(len(pDUSessionEstablishmentAccept.SessionAMBR.Octet)))

	qoSRules := nasType.QoSRules{
		{
			Identifier: smContext.defRuleID,
			DQR:        true,
			Operation:  nasType.OperationCodeCreateNewQoSRule,
			Precedence: 255,
			QFI:        sessRule.DefQosQFI,
			PacketFilterList: nasType.PacketFilterList{
				{
					Identifier: 1,
					Direction:  nasType.PacketFilterDirectionBidirectional,
					Components: nasType.PacketFilterComponentList{
						&nasType.PacketFilterMatchAll{},
					},
				},
			},
		},
	}

	for _, pccRule := range smContext.PCCRules {
		if qosRule, err1 := pccRule.BuildNasQoSRule(smContext,
			nasType.OperationCodeCreateNewQoSRule); err1 != nil {
			logger.GsmLog.Warnln("Create QoS rule from pcc error ", err1)
		} else {
			if ruleID, err2 := smContext.QoSRuleIDGenerator.Allocate(); err2 != nil {
				return nil, err2
			} else {
				qosRule.Identifier = uint8(ruleID)
				smContext.PCCRuleIDToQoSRuleID[pccRule.PccRuleId] = uint8(ruleID)
			}
			qoSRules = append(qoSRules, *qosRule)
		}
	}

	qosRulesBytes, errMarshalBinary := qoSRules.MarshalBinary()
	if errMarshalBinary != nil {
		return nil, errMarshalBinary
	}

	pDUSessionEstablishmentAccept.AuthorizedQosRules.SetLen(uint16(len(qosRulesBytes)))
	pDUSessionEstablishmentAccept.AuthorizedQosRules.SetQosRule(qosRulesBytes)

	if smContext.PDUAddress != nil {
		addr, addrLen := smContext.PDUAddressToNAS()
		pDUSessionEstablishmentAccept.PDUAddress = nasType.
			NewPDUAddress(nasMessage.PDUSessionEstablishmentAcceptPDUAddressType)
		pDUSessionEstablishmentAccept.PDUAddress.SetLen(addrLen)
		pDUSessionEstablishmentAccept.PDUAddress.SetPDUSessionTypeValue(smContext.SelectedPDUSessionType)
		pDUSessionEstablishmentAccept.PDUAddress.SetPDUAddressInformation(addr)
	}

	authDescs := nasType.QoSFlowDescs{}
	dafaultAuthDesc := nasType.QoSFlowDesc{}
	dafaultAuthDesc.QFI = sessRule.DefQosQFI
	dafaultAuthDesc.OperationCode = nasType.OperationCodeCreateNewQoSFlowDescription
	parameter := new(nasType.QoSFlow5QI)
	parameter.FiveQI = uint8(authDefQos.Var5qi)
	dafaultAuthDesc.Parameters = append(dafaultAuthDesc.Parameters, parameter)
	authDescs = append(authDescs, dafaultAuthDesc)
	for _, qosFlow := range smContext.AdditonalQosFlows {
		if qosDesc, e := qosFlow.BuildNasQoSDesc(nasType.OperationCodeCreateNewQoSFlowDescription); e != nil {
			logger.GsmLog.Warnf("Create QoS Desc from qos flow error: %s\n", e)
		} else {
			authDescs = append(authDescs, qosDesc)
		}
	}
	qosDescBytes, errMarshalBinary := authDescs.MarshalBinary()
	if errMarshalBinary != nil {
		return nil, errMarshalBinary
	}
	pDUSessionEstablishmentAccept.AuthorizedQosFlowDescriptions = nasType.
		NewAuthorizedQosFlowDescriptions(nasMessage.PDUSessionEstablishmentAcceptAuthorizedQosFlowDescriptionsType)
	pDUSessionEstablishmentAccept.AuthorizedQosFlowDescriptions.SetLen(uint16(len(qosDescBytes)))
	pDUSessionEstablishmentAccept.SetQoSFlowDescriptions(qosDescBytes)

	pDUSessionEstablishmentAccept.SNSSAI = nasType.NewSNSSAI(nasMessage.ULNASTransportSNSSAIType)
	pDUSessionEstablishmentAccept.SNSSAI.SetSST(uint8(smContext.SNssai.Sst))
	if smContext.SNssai.Sd == "" {
		// SST-only S-NSSAI (no SD): encode length 1. Encoding SD=000000 (length 4)
		// for an SST-only slice makes strict UEs treat it as a different slice from
		// their SST-only Allowed NSSAI and regular-deactivate the PDU session (#36).
		pDUSessionEstablishmentAccept.SNSSAI.SetLen(1)
	} else {
		var sd [3]uint8
		byteArray, errDecodeString := hex.DecodeString(smContext.SNssai.Sd)
		if errDecodeString != nil {
			return nil, errDecodeString
		}
		copy(sd[:], byteArray)
		pDUSessionEstablishmentAccept.SNSSAI.SetLen(4)
		pDUSessionEstablishmentAccept.SNSSAI.SetSD(sd)
	}

	pDUSessionEstablishmentAccept.DNN = nasType.NewDNN(nasMessage.ULNASTransportDNNType)
	pDUSessionEstablishmentAccept.DNN.SetDNN(smContext.Dnn)

	if smContext.ProtocolConfigurationOptions.DNSIPv4Request ||
		smContext.ProtocolConfigurationOptions.DNSIPv6Request ||
		smContext.ProtocolConfigurationOptions.PCSCFIPv4Request ||
		smContext.ProtocolConfigurationOptions.IPv4LinkMTURequest ||
		smContext.ProtocolConfigurationOptions.IPCPRequest {
		pDUSessionEstablishmentAccept.ExtendedProtocolConfigurationOptions = nasType.NewExtendedProtocolConfigurationOptions(
			nasMessage.PDUSessionEstablishmentAcceptExtendedProtocolConfigurationOptionsType,
		)
		protocolConfigurationOptions := nasConvert.NewProtocolConfigurationOptions()

		// IPv4 DNS
		if smContext.ProtocolConfigurationOptions.DNSIPv4Request {
			errAddDNSServerIPv4Address := protocolConfigurationOptions.AddDNSServerIPv4Address(smContext.DNNInfo.DNS.IPv4Addr)
			if errAddDNSServerIPv4Address != nil {
				logger.GsmLog.Warnln("Error while adding DNS IPv4 Addr: ", errAddDNSServerIPv4Address)
			}
		}

		// IPv6 DNS
		if smContext.ProtocolConfigurationOptions.DNSIPv6Request {
			errAddDNSServerIPv6Address := protocolConfigurationOptions.AddDNSServerIPv6Address(smContext.DNNInfo.DNS.IPv6Addr)
			if errAddDNSServerIPv6Address != nil {
				logger.GsmLog.Warnln("Error while adding DNS IPv6 Addr: ", errAddDNSServerIPv6Address)
			}
		}

		// IPv4 PCSCF (need for ims DNN)
		if smContext.ProtocolConfigurationOptions.PCSCFIPv4Request {
			errAddPCSCFIPv4Address := protocolConfigurationOptions.AddPCSCFIPv4Address(smContext.DNNInfo.PCSCF.IPv4Addr)
			if errAddPCSCFIPv4Address != nil {
				logger.GsmLog.Warnln("Error while adding PCSCF IPv4 Addr: ", errAddPCSCFIPv4Address)
			}
		}

		// MTU
		if smContext.ProtocolConfigurationOptions.IPv4LinkMTURequest {
			errAddIPv4LinkMTU := protocolConfigurationOptions.AddIPv4LinkMTU(1280)
			if errAddIPv4LinkMTU != nil {
				logger.GsmLog.Warnln("Error while adding MTU: ", errAddIPv4LinkMTU)
			}
		}

		// Legacy IPCP (PPP, 0x8021) DNS negotiation. Some UEs (e.g. Qualcomm-based
		// modems) only accept DNS via IPCP and ignore the 0x000d container. Reply to
		// the UE's IPCP Configure-Request with a Configure-Nak (code 0x03) carrying the
		// primary/secondary DNS server addresses (RFC 1877 options 129/131).
		if smContext.ProtocolConfigurationOptions.IPCPRequest {
			dns4 := smContext.DNNInfo.DNS.IPv4Addr.To4()
			if dns4 != nil {
				// Secondary DNS: use configured IPv6? no; fall back to a public resolver.
				sec := net.IPv4(8, 8, 4, 4).To4()
				ipcp := []byte{
					0x03, // Code: Configure-Nak
					smContext.ProtocolConfigurationOptions.IPCPIdentifier, // Identifier (echo request)
					0x00, 0x10, // Length = 16 bytes (header 4 + 6 + 6)
					0x81, 0x06, dns4[0], dns4[1], dns4[2], dns4[3], // Opt 129: Primary DNS
					0x83, 0x06, sec[0], sec[1], sec[2], sec[3], // Opt 131: Secondary DNS
				}
				ipcpUnit := &nasConvert.ProtocolOrContainerUnit{
					ProtocolOrContainerID: nasMessage.InternetProtocolControlProtocolUL, // 0x8021
					LengthOfContents:      uint8(len(ipcp)),
					Contents:              ipcp,
				}
				protocolConfigurationOptions.ProtocolOrContainerList = append(
					protocolConfigurationOptions.ProtocolOrContainerList, ipcpUnit)
				logger.GsmLog.Infof("Added IPCP Configure-Nak with DNS %s to PDU Session Establishment Accept", dns4.String())
			} else {
				logger.GsmLog.Warnln("IPCP DNS requested but DNNInfo has no IPv4 DNS configured")
			}
		}

		pcoContents := protocolConfigurationOptions.Marshal()
		pcoContentsLength := len(pcoContents)
		pDUSessionEstablishmentAccept.
			ExtendedProtocolConfigurationOptions.
			SetLen(uint16(pcoContentsLength))
		pDUSessionEstablishmentAccept.
			ExtendedProtocolConfigurationOptions.
			SetExtendedProtocolConfigurationOptionsContents(pcoContents)
	}
	return m.PlainNasEncode()
}

func BuildGSMPDUSessionEstablishmentReject(smContext *SMContext, cause uint8) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionEstablishmentReject)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionEstablishmentReject = nasMessage.NewPDUSessionEstablishmentReject(0x0)
	pDUSessionEstablishmentReject := m.PDUSessionEstablishmentReject

	pDUSessionEstablishmentReject.SetMessageType(nas.MsgTypePDUSessionEstablishmentReject)
	pDUSessionEstablishmentReject.SetPTI(smContext.Pti)
	pDUSessionEstablishmentReject.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pDUSessionEstablishmentReject.SetPDUSessionID(uint8(smContext.PDUSessionID))
	pDUSessionEstablishmentReject.SetCauseValue(cause)

	return m.PlainNasEncode()
}

// BuildGSMPDUSessionReleaseCommand makes a plain NAS message.
//
// If isTriggeredByUE is true, the PTI field of the constructed NAS message is
// the value of smContext.Pti which is received from UE, otherwise it is 0.
// ref. 6.3.3.2 Network-requested PDU session release procedure initiation in TS24.501.
func BuildGSMPDUSessionReleaseCommand(smContext *SMContext, cause uint8, isTriggeredByUE bool) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionReleaseCommand)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionReleaseCommand = nasMessage.NewPDUSessionReleaseCommand(0x0)
	pDUSessionReleaseCommand := m.PDUSessionReleaseCommand

	pDUSessionReleaseCommand.SetMessageType(nas.MsgTypePDUSessionReleaseCommand)
	pDUSessionReleaseCommand.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pDUSessionReleaseCommand.SetPDUSessionID(uint8(smContext.PDUSessionID))

	if isTriggeredByUE {
		pDUSessionReleaseCommand.SetPTI(smContext.Pti)
	} else {
		pDUSessionReleaseCommand.SetPTI(0x00)
	}
	pDUSessionReleaseCommand.SetCauseValue(cause)

	return m.PlainNasEncode()
}

// BuildGSMPDUSessionModificationCommand builds a network-requested PDU Session
// Modification Command carrying the Authorized QoS Rules and QoS Flow
// Descriptions for the QoS flows that were newly added or are to be modified
// (state QoSFlowUnset / QoSFlowToBeModify) — e.g. as a result of a PCF
// Npcf_PolicyAuthorization app-session that installs a new PCC rule with a
// different 5QI. It is used by the network-initiated modification triggered
// from the SM policy update-notify handler.
func BuildGSMPDUSessionModificationCommand(smContext *SMContext) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionModificationCommand)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionModificationCommand = nasMessage.NewPDUSessionModificationCommand(0x0)
	pDUSessionModificationCommand := m.PDUSessionModificationCommand

	pDUSessionModificationCommand.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pDUSessionModificationCommand.SetPDUSessionID(uint8(smContext.PDUSessionID))
	// Network-requested modification: no procedure transaction identity (PTI = 0).
	pDUSessionModificationCommand.SetPTI(0x00)
	pDUSessionModificationCommand.SetMessageType(nas.MsgTypePDUSessionModificationCommand)

	// Authorized QoS Rules: one per PCC rule whose QoS flow is new / to-be-modified.
	qoSRules := nasType.QoSRules{}
	for _, pccRule := range smContext.PCCRules {
		qosFlow, ok := smContext.AdditonalQosFlows[pccRule.QFI]
		if !ok || (qosFlow.State != QoSFlowUnset && qosFlow.State != QoSFlowToBeModify) {
			continue
		}
		qosRule, err := pccRule.BuildNasQoSRule(smContext, nasType.OperationCodeCreateNewQoSRule)
		if err != nil {
			logger.GsmLog.Warnf("Create QoS rule from pcc error: %s", err)
			continue
		}
		// Reuse an already-assigned QoS rule id if present, otherwise allocate one.
		if ruleID, exist := smContext.PCCRuleIDToQoSRuleID[pccRule.PccRuleId]; exist {
			qosRule.Identifier = ruleID
		} else {
			newID, errAlloc := smContext.QoSRuleIDGenerator.Allocate()
			if errAlloc != nil {
				return nil, errAlloc
			}
			qosRule.Identifier = uint8(newID)
			smContext.PCCRuleIDToQoSRuleID[pccRule.PccRuleId] = uint8(newID)
		}
		qoSRules = append(qoSRules, *qosRule)
	}
	if len(qoSRules) > 0 {
		qosRulesBytes, err := qoSRules.MarshalBinary()
		if err != nil {
			return nil, err
		}
		pDUSessionModificationCommand.AuthorizedQosRules =
			nasType.NewAuthorizedQosRules(nasMessage.PDUSessionModificationCommandAuthorizedQosRulesType)
		pDUSessionModificationCommand.AuthorizedQosRules.SetLen(uint16(len(qosRulesBytes)))
		pDUSessionModificationCommand.AuthorizedQosRules.SetQosRule(qosRulesBytes)
	}

	// Authorized QoS Flow Descriptions: carry the 5QI (and GBR bitrates for GBR
	// flows) for each new / to-be-modified flow.
	authDescs := nasType.QoSFlowDescs{}
	for _, qosFlow := range smContext.AdditonalQosFlows {
		if qosFlow.State != QoSFlowUnset && qosFlow.State != QoSFlowToBeModify {
			continue
		}
		if qosDesc, err := qosFlow.BuildNasQoSDesc(nasType.OperationCodeCreateNewQoSFlowDescription); err != nil {
			logger.GsmLog.Warnf("Create QoS Desc from qos flow error: %s", err)
		} else {
			authDescs = append(authDescs, qosDesc)
		}
	}
	if len(authDescs) > 0 {
		qosDescBytes, err := authDescs.MarshalBinary()
		if err != nil {
			return nil, err
		}
		pDUSessionModificationCommand.AuthorizedQosFlowDescriptions =
			nasType.NewAuthorizedQosFlowDescriptions(nasMessage.PDUSessionModificationCommandAuthorizedQosFlowDescriptionsType)
		pDUSessionModificationCommand.AuthorizedQosFlowDescriptions.SetLen(uint16(len(qosDescBytes)))
		pDUSessionModificationCommand.AuthorizedQosFlowDescriptions.SetQoSFlowDescriptions(qosDescBytes)
	}

	return m.PlainNasEncode()
}

// BuildGSMPDUSessionModificationCommandForRemoval builds a network-requested PDU
// Session Modification Command that DELETES the given QoS rules and QoS flow
// descriptions from the UE - e.g. when an AsSessionWithQoS subscription is deleted,
// downgrading the UE back to its default flow. qosRuleIDs are the NAS QoS rule
// identifiers and qfis the QoS flow identifiers to remove.
func BuildGSMPDUSessionModificationCommandForRemoval(
	smContext *SMContext, qosRuleIDs, qfis []uint8,
) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionModificationCommand)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionModificationCommand = nasMessage.NewPDUSessionModificationCommand(0x0)
	cmd := m.PDUSessionModificationCommand

	cmd.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	cmd.SetPDUSessionID(uint8(smContext.PDUSessionID))
	cmd.SetPTI(0x00) // network-requested: no procedure transaction identity
	cmd.SetMessageType(nas.MsgTypePDUSessionModificationCommand)

	// Authorized QoS Rules: "delete existing QoS rule" entries. Hand-built to be
	// spec-clean - a delete rule's content is exactly one byte (rule op-code + DQR +
	// number-of-packet-filters=0), with no packet filters / precedence / QFI. Each
	// entry: [identifier][length=0x0001][op<<5].
	if len(qosRuleIDs) > 0 {
		ruleBytes := make([]byte, 0, len(qosRuleIDs)*4)
		for _, rid := range qosRuleIDs {
			ruleBytes = append(ruleBytes,
				rid, 0x00, 0x01, byte(nasType.OperationCodeDeleteExistingQoSRule)<<5)
		}
		cmd.AuthorizedQosRules =
			nasType.NewAuthorizedQosRules(nasMessage.PDUSessionModificationCommandAuthorizedQosRulesType)
		cmd.AuthorizedQosRules.SetLen(uint16(len(ruleBytes)))
		cmd.AuthorizedQosRules.SetQosRule(ruleBytes)
	}

	// Authorized QoS Flow Descriptions: "delete existing QoS flow description".
	if len(qfis) > 0 {
		descs := nasType.QoSFlowDescs{}
		for _, qfi := range qfis {
			descs = append(descs, nasType.QoSFlowDesc{
				QFI:           qfi,
				OperationCode: nasType.OperationCodeDeleteExistingQoSFlowDescription,
			})
		}
		descBytes, err := descs.MarshalBinary()
		if err != nil {
			return nil, err
		}
		cmd.AuthorizedQosFlowDescriptions =
			nasType.NewAuthorizedQosFlowDescriptions(nasMessage.PDUSessionModificationCommandAuthorizedQosFlowDescriptionsType)
		cmd.AuthorizedQosFlowDescriptions.SetLen(uint16(len(descBytes)))
		cmd.AuthorizedQosFlowDescriptions.SetQoSFlowDescriptions(descBytes)
	}

	return m.PlainNasEncode()
}

func BuildGSMPDUSessionReleaseReject(smContext *SMContext) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionReleaseReject)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionReleaseReject = nasMessage.NewPDUSessionReleaseReject(0x0)
	pDUSessionReleaseReject := m.PDUSessionReleaseReject

	pDUSessionReleaseReject.SetMessageType(nas.MsgTypePDUSessionReleaseReject)
	pDUSessionReleaseReject.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)

	pDUSessionReleaseReject.SetPDUSessionID(uint8(smContext.PDUSessionID))

	pDUSessionReleaseReject.SetPTI(smContext.Pti)
	// TODO: fix to real value
	pDUSessionReleaseReject.SetCauseValue(nasMessage.Cause5GSMRequestRejectedUnspecified)

	return m.PlainNasEncode()
}

func BuildGSMPDUSessionModificationReject(smContext *SMContext) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionModificationReject)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionModificationReject = nasMessage.NewPDUSessionModificationReject(0x0)
	pDUSessionModificationReject := m.PDUSessionModificationReject

	pDUSessionModificationReject.SetMessageType(nas.MsgTypePDUSessionModificationReject)
	pDUSessionModificationReject.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pDUSessionModificationReject.SetPDUSessionID(uint8(smContext.PDUSessionID))
	pDUSessionModificationReject.SetPTI(smContext.Pti)
	pDUSessionModificationReject.SetCauseValue(nasMessage.Cause5GSMMessageTypeNonExistentOrNotImplemented)

	return m.PlainNasEncode()
}
