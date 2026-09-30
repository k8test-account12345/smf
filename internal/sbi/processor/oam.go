package processor

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/logger"
	"github.com/free5gc/smf/pkg/factory"
)

type PDUSessionInfo struct {
	Supi         string
	PDUSessionID string
	Dnn          string
	Sst          string
	Sd           string
	AnType       models.AccessType
	PDUAddress   string
	SessionRule  models.SessionRule
	UpCnxState   models.UpCnxState
	Tunnel       context.UPTunnel
}

func (p *Processor) HandleOAMGetUEPDUSessionInfo(c *gin.Context, smContextRef string) {
	smContext := context.GetSMContextByRef(smContextRef)
	if smContext == nil {
		c.JSON(http.StatusNotFound, nil)
		return
	}

	pduSessionInfo := &PDUSessionInfo{
		Supi:         smContext.Supi,
		PDUSessionID: strconv.Itoa(int(smContext.PDUSessionID)),
		Dnn:          smContext.Dnn,
		Sst:          strconv.Itoa(int(smContext.SNssai.Sst)),
		Sd:           smContext.SNssai.Sd,
		AnType:       smContext.AnType,
		PDUAddress:   smContext.PDUAddress.String(),
		UpCnxState:   smContext.UpCnxState,
		// Tunnel: context.UPTunnel{
		// 	//UpfRoot:  smContext.Tunnel.UpfRoot,
		// 	ULCLRoot: smContext.Tunnel.UpfRoot,
		// },
	}
	c.JSON(http.StatusOK, pduSessionInfo)
}

func (p *Processor) HandleGetSMFUserPlaneInfo(c *gin.Context) {
	c.JSON(http.StatusOK, factory.SmfConfig.Configuration.UserPlaneInformation)
}

// HandleOAMListSessions returns a summary of all active PDU sessions (every UE
// currently registered with an established session), for AF/NEF listing. It also
// asynchronously reaps superseded orphan contexts so the list self-cleans.
func (p *Processor) HandleOAMListSessions(c *gin.Context) {
	go p.ReapOrphanedSessions()
	c.JSON(http.StatusOK, gin.H{"sessions": context.ListActiveSessions()})
}

// ReapOrphanedSessions tears down every superseded orphan SM context (proper
// RemoveSMContextFromAllNF cleanup: PCF SM-policy termination, UDM unsubscribe,
// context removal). Returns how many were reaped.
func (p *Processor) ReapOrphanedSessions() int {
	refs := context.ListOrphanedRefs()
	for _, ref := range refs {
		if smCtx := context.GetSMContextByRef(ref); smCtx != nil {
			smCtx.Log.Infof("Reaping orphaned SM context [%s] (superseded by a newer session)", ref)
			p.RemoveSMContextFromAllNF(smCtx, false)
		}
	}
	if len(refs) > 0 {
		logger.CtxLog.Infof("Reaped %d orphaned SM context(s)", len(refs))
	}
	return len(refs)
}

// HandleOAMReleaseSession force-releases a specific SM context by ref (proper
// teardown), for on-demand cleanup of a stale/stuck session.
func (p *Processor) HandleOAMReleaseSession(c *gin.Context, ref string) {
	smCtx := context.GetSMContextByRef(ref)
	if smCtx == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no session with ref " + ref})
		return
	}
	supi, gpsi, pid := smCtx.Supi, smCtx.Gpsi, smCtx.PDUSessionID
	smCtx.Log.Infof("OAM-requested release of SM context [%s]", ref)
	p.RemoveSMContextFromAllNF(smCtx, false)
	c.JSON(http.StatusOK, gin.H{"released": ref, "supi": supi, "gpsi": gpsi, "pduSessionId": pid})
}

// HandleOAMGetSessionAMBR returns the currently authorized session-AMBR for the
// UE identified by GPSI (MSISDN). This is the value the UPF enforces and what an
// AF/NEF "read current AMBR" call surfaces.
func (p *Processor) HandleOAMGetSessionAMBR(c *gin.Context, gpsi string) {
	smContext := context.GetSMContextByGpsi(gpsi)
	if smContext == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no active PDU session for gpsi " + gpsi})
		return
	}
	sr := smContext.SelectedSessionRule()
	if sr == nil || sr.AuthSessAmbr == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no session-AMBR for gpsi " + gpsi})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"supi":         smContext.Supi,
		"gpsi":         gpsi,
		"pduSessionId": smContext.PDUSessionID,
		"sessionAmbr":  sr.AuthSessAmbr,
	})
}

// HandleOAMSetSessionAMBR changes the session-AMBR on the fly for the UE
// identified by GPSI. It updates the UPF QER only (no N1/N2), so the UE and gNB
// are not reconfigured over the air.
func (p *Processor) HandleOAMSetSessionAMBR(c *gin.Context, gpsi string) {
	var body models.Ambr
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Uplink == "" || body.Downlink == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "both uplink and downlink are required (e.g. \"10 Mbps\")"})
		return
	}

	smContext := context.GetSMContextByGpsi(gpsi)
	if smContext == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no active PDU session for gpsi " + gpsi})
		return
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	smContext.SetState(context.ModificationPending)
	if err := smContext.ApplySessionAMBR(body.Uplink, body.Downlink); err != nil {
		smContext.SetState(context.Active)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Push the updated QER to the UPF (PFCP Session Modification -> UpdateQER).
	// No N1N2MessageTransfer is issued, so no UE/RAN radio reconfiguration.
	ActivateUPFSession(smContext, nil)
	smContext.SetState(context.Active)

	c.JSON(http.StatusOK, gin.H{
		"supi":         smContext.Supi,
		"gpsi":         gpsi,
		"pduSessionId": smContext.PDUSessionID,
		"sessionAmbr":  smContext.SelectedSessionRule().AuthSessAmbr,
	})
}
