package processor

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/smf/EventExposure"
	smf_context "github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/logger"
)

func (p *Processor) HandleChargingNotification(
	c *gin.Context,
	chargingNotifyRequest models.ChargingNotifyRequest,
	smContextRef string,
) {
	logger.ChargingLog.Info("Handle Charging Notification")

	problemDetails := p.chargingNotificationProcedure(chargingNotifyRequest, smContextRef)
	if problemDetails == nil {
		c.Status(http.StatusNoContent)
		return
	}
	c.JSON(int(problemDetails.Status), problemDetails)
}

// While receive Charging Notification from CHF, SMF will send Charging Information to CHF and update UPF
// The Charging Notification will be sent when CHF found the changes of the quota file.
func (p *Processor) chargingNotificationProcedure(
	req models.ChargingNotifyRequest, smContextRef string,
) *models.ProblemDetails {
	if smContext := smf_context.GetSMContextByRef(smContextRef); smContext != nil {
		smContext.SMLock.Lock()
		defer smContext.SMLock.Unlock()
		upfUrrMap := make(map[string][]*smf_context.URR)
		for _, reauthorizeDetail := range req.ReauthorizationDetails {
			rg := reauthorizeDetail.RatingGroup
			logger.ChargingLog.Infof("Force update charging information for rating group %d", rg)
			for _, urr := range smContext.UrrUpfMap {
				chgInfo := smContext.ChargingInfo[urr.URRID]
				if chgInfo.RatingGroup == rg ||
					chgInfo.ChargingLevel == smf_context.PduSessionCharging {
					logger.ChargingLog.Tracef("Query URR (%d) for Rating Group (%d)", urr.URRID, rg)
					upfId := smContext.ChargingInfo[urr.URRID].UpfId
					upfUrrMap[upfId] = append(upfUrrMap[upfId], urr)
				}
			}
		}
		for upfId, urrList := range upfUrrMap {
			upf := smf_context.GetUpfById(upfId)
			if upf == nil {
				logger.ChargingLog.Warnf("Cound not find upf %s", upfId)
				continue
			}
			QueryReport(smContext, upf, urrList, models.ChfConvergedChargingTriggerType_FORCED_REAUTHORISATION)
		}
		p.ReportUsageAndUpdateQuota(smContext)
	} else {
		detail := fmt.Sprintf("SM Context [%s] Not Found ", smContextRef)
		return openapi.ProblemDetailsDataNotFound(detail)
	}

	return nil
}

func (p *Processor) HandleSMPolicyUpdateNotify(
	c *gin.Context,
	request models.SmPolicyNotification,
	smContextRef string,
) {
	logger.PduSessLog.Infoln("In HandleSMPolicyUpdateNotify")
	decision := request.SmPolicyDecision
	smContext := smf_context.GetSMContextByRef(smContextRef)

	if smContext == nil {
		logger.PduSessLog.Errorf("SMContext[%s] not found", smContextRef)
		c.Status(http.StatusBadRequest)
		return
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	smContext.CheckState(smf_context.Active)
	// Wait till the state becomes Active again
	// TODO: implement waiting in concurrent architecture

	smContext.SetState(smf_context.ModificationPending)

	// Update SessionRule from decision
	if err := smContext.ApplySessionRules(decision); err != nil {
		// TODO: Fill the error body
		smContext.Log.Errorf("SMPolicyUpdateNotify err: %v", err)
		c.Status(http.StatusBadRequest)
		return
	}

	// TODO: Response data type -
	// [200 OK] UeCampingRep
	// [200 OK] array(PartialSuccessReport)
	// [400 Bad Request] ErrorReport
	if err := smContext.ApplyPccRules(decision); err != nil {
		smContext.Log.Errorf("apply sm policy decision error: %+v", err)
		// TODO: Fill the error body
		c.Status(http.StatusBadRequest)
		return
	}

	smContext.SendUpPathChgNotification("EARLY", SendUpPathChgEventExposureNotification)

	ActivateUPFSession(smContext, nil)

	smContext.SendUpPathChgNotification("LATE", SendUpPathChgEventExposureNotification)

	// Network(PCF)-initiated PDU Session Modification: if the policy update added
	// or changed a QoS flow (e.g. a new 5QI from a PolicyAuthorization app-session),
	// signal it to the UE/RAN so the change actually takes effect over the air.
	p.sendNetworkInitiatedModification(smContext)

	// NOTE: network-initiated flow-REMOVAL signalling is reverted (first-version
	// behaviour): TURBO OFF removes the flow in the core only, without sending an
	// extra RRC/DRB reconfiguration to the UE (which was a second radio-drop
	// opportunity). The flow clears on the UE at its next re-establishment.
	// (sendNetworkInitiatedFlowRemoval remains defined but is no longer called.)

	smContext.PostRemoveDataPath()

	c.Status(http.StatusNoContent)
}

// sendNetworkInitiatedModification sends a network-requested PDU Session
// Modification Command (N1) plus the PDU Session Resource Modify Request (N2)
// to the AMF via N1N2MessageTransfer, when the current SM policy decision has
// introduced QoS flows that must be signalled to the UE. If there is nothing to
// signal (e.g. a UPF-only change) it is a no-op.
func (p *Processor) sendNetworkInitiatedModification(smContext *smf_context.SMContext) {
	needSignal := false
	for _, qosFlow := range smContext.AdditonalQosFlows {
		if qosFlow.State == smf_context.QoSFlowUnset || qosFlow.State == smf_context.QoSFlowToBeModify {
			needSignal = true
			break
		}
	}
	if !needSignal {
		smContext.Log.Infoln("SMPolicyUpdateNotify: no QoS flow change to signal to UE")
		return
	}

	n1Buf, err := smf_context.BuildGSMPDUSessionModificationCommand(smContext)
	if err != nil {
		smContext.Log.Errorf("Build PDUSessionModificationCommand failed: %+v", err)
		return
	}
	n2Buf, err := smf_context.BuildPDUSessionResourceModifyRequestTransfer(smContext)
	if err != nil {
		smContext.Log.Errorf("Build PDUSessionResourceModifyRequestTransfer failed: %+v", err)
		return
	}
	if len(n2Buf) == 0 {
		// Nothing to add/modify at the NG-RAN (no flow in QoSFlowUnset/QoSFlowToBeModify);
		// sendPduSessionModificationN1N2 always builds an N2 container, so sending with an
		// empty N2 would be malformed. Skip it.
		smContext.Log.Infoln("SMPolicyUpdateNotify: no QoS flow add/modify for NG-RAN; not sending N1N2")
		return
	}
	if p.sendPduSessionModificationN1N2(smContext, n1Buf, n2Buf) {
		smContext.Log.Infof("Network-initiated PDU Session Modification sent to UE[%s] PDUSession[%d]",
			smContext.Supi, smContext.PDUSessionID)
	}
}

// sendNetworkInitiatedFlowRemoval signals the UE to delete the given QoS rules /
// flows (network-initiated downgrade), e.g. when an AsSessionWithQoS subscription
// is deleted and the UE should fall back to its default flow.
func (p *Processor) sendNetworkInitiatedFlowRemoval(
	smContext *smf_context.SMContext, qosRuleIDs, qfis []uint8,
) {
	if len(qosRuleIDs) == 0 && len(qfis) == 0 {
		return
	}
	n1Buf, err := smf_context.BuildGSMPDUSessionModificationCommandForRemoval(smContext, qosRuleIDs, qfis)
	if err != nil {
		smContext.Log.Errorf("Build PDUSessionModificationCommand (removal) failed: %+v", err)
		return
	}
	n2Buf, err := smf_context.BuildPDUSessionResourceModifyRequestTransferForRelease(qfis)
	if err != nil {
		smContext.Log.Errorf("Build PDUSessionResourceModifyRequestTransfer (release) failed: %+v", err)
		return
	}
	if p.sendPduSessionModificationN1N2(smContext, n1Buf, n2Buf) {
		smContext.Log.Infof("Network-initiated PDU Session Modification (QoS flow removal) sent to UE[%s] PDUSession[%d]",
			smContext.Supi, smContext.PDUSessionID)
	}
}

// sendPduSessionModificationN1N2 sends a PDU Session Modification Command (N1) plus
// the PDU Session Resource Modify Request (N2) to the AMF via N1N2MessageTransfer.
func (p *Processor) sendPduSessionModificationN1N2(
	smContext *smf_context.SMContext, n1Buf, n2Buf []byte,
) bool {
	n1n2Request := models.N1N2MessageTransferRequest{
		BinaryDataN1Message:     n1Buf,
		BinaryDataN2Information: n2Buf,
		JsonData: &models.N1N2MessageTransferReqData{
			PduSessionId: smContext.PDUSessionID,
			N1MessageContainer: &models.N1MessageContainer{
				N1MessageClass:   "SM",
				N1MessageContent: &models.RefToBinaryData{ContentId: "GSM_NAS"},
			},
			N2InfoContainer: &models.N2InfoContainer{
				N2InformationClass: models.N2InformationClass_SM,
				SmInfo: &models.N2SmInformation{
					PduSessionId: smContext.PDUSessionID,
					N2InfoContent: &models.N2InfoContent{
						NgapIeType: models.AmfCommunicationNgapIeType_PDU_RES_MOD_REQ,
						NgapData:   &models.RefToBinaryData{ContentId: "N2SmInformation"},
					},
					SNssai: smContext.SNssai,
				},
			},
		},
	}

	ctx, _, err := smf_context.GetSelf().GetTokenCtx(models.ServiceName_NAMF_COMM, models.NrfNfManagementNfType_AMF)
	if err != nil {
		smContext.Log.Warnf("Get namf-comm token failed: %+v", err)
		return false
	}
	rspData, err := p.Consumer().
		N1N2MessageTransfer(ctx, smContext.Supi, n1n2Request, smContext.CommunicationClientApiPrefix)
	if err != nil || rspData == nil {
		logger.ConsumerLog.Warnf("N1N2MessageTransfer for network-initiated PDUSessionModification failed: %+v", err)
		return false
	}
	if rspData.Cause == models.N1N2MessageTransferCause_N1_MSG_NOT_TRANSFERRED {
		smContext.Log.Warnf("N1N2MessageTransfer cause: %v", rspData.Cause)
	}
	return true
}

func SendUpPathChgEventExposureNotification(
	uri string, notification *models.NsmfEventExposureNotification,
) {
	configuration := EventExposure.NewConfiguration()
	client := EventExposure.NewAPIClient(configuration)
	request := &EventExposure.CreateIndividualSubcriptionMyNotificationPostRequest{
		NsmfEventExposureNotification: notification,
	}
	_, err := client.
		SubscriptionsCollectionApi.
		CreateIndividualSubcriptionMyNotificationPost(context.Background(), uri, request)

	switch err := err.(type) {
	case openapi.GenericOpenAPIError:
		logger.PduSessLog.Warnf("SMF Event Exposure Notification Error[%s]", err.Error())
	case error:
		logger.PduSessLog.Warnf("SMF Event Exposure Notification Failed[%s]", err.Error())
	case nil:
		logger.PduSessLog.Tracef("SMF Event Exposure Notification Success")
	default:
		logger.PduSessLog.Warnf("SMF Event Exposure Notification Unknown Error: %+v", err)
	}
}
