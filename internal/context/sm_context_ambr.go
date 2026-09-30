package context

import (
	"fmt"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/smf/internal/logger"
	"github.com/free5gc/smf/internal/util"
)

// SessionSummary is a compact view of an active PDU session, for OAM/AF listing.
type SessionSummary struct {
	Ref          string       `json:"ref"`
	Supi         string       `json:"supi"`
	Gpsi         string       `json:"gpsi"`
	PDUSessionID int32        `json:"pduSessionId"`
	Dnn          string       `json:"dnn"`
	Ipv4         string       `json:"ipv4,omitempty"`
	Orphan       bool         `json:"orphan"`
	SessionAmbr  *models.Ambr `json:"sessionAmbr,omitempty"`
}

// ListActiveSessions returns a summary of every SM context currently in the pool
// (i.e. every UE with an established PDU session), for the OAM "list sessions" API.
func ListActiveSessions() []SessionSummary {
	out := []SessionSummary{}
	smContextPool.Range(func(key, value interface{}) bool {
		c, ok := value.(*SMContext)
		if !ok || c == nil {
			return true
		}
		s := SessionSummary{
			Ref:          c.Ref,
			Supi:         c.Supi,
			Gpsi:         c.Gpsi,
			PDUSessionID: c.PDUSessionID,
			Dnn:          c.Dnn,
		}
		if c.PDUAddress != nil {
			s.Ipv4 = c.PDUAddress.String()
		}
		if sr := c.SelectedSessionRule(); sr != nil {
			s.SessionAmbr = sr.AuthSessAmbr
		}
		// mark superseded orphans (not the canonicalRef-current context)
		if curRef, err := ResolveRef(c.Supi, c.PDUSessionID); err == nil && curRef != c.Ref {
			s.Orphan = true
		}
		out = append(out, s)
		return true
	})
	return out
}

// ApplySessionAMBR changes the PDU session's aggregate maximum bit rate on the
// fly. It rewrites the authorized session-AMBR and updates the per-UPF
// session-AMBR QER ("ambrQER") MBR in place, marking it RULE_UPDATE so the next
// PFCP Session Modification carries an UpdateQER (rather than a duplicate
// Create). It performs NO N1/N2 signalling: the new rate is enforced purely at
// the UPF, so neither the UE nor the gNB is reconfigured over the air.
func (c *SMContext) ApplySessionAMBR(uplink, downlink string) error {
	sessionRule := c.SelectedSessionRule()
	if sessionRule == nil || sessionRule.AuthSessAmbr == nil {
		return fmt.Errorf("no selected session rule / AuthSessAmbr for supi[%s]", c.Supi)
	}

	ulKbps, err := util.BitRateTokbps(uplink)
	if err != nil {
		return fmt.Errorf("parse uplink AMBR %q: %v", uplink, err)
	}
	dlKbps, err := util.BitRateTokbps(downlink)
	if err != nil {
		return fmt.Errorf("parse downlink AMBR %q: %v", downlink, err)
	}

	sessionRule.AuthSessAmbr.Uplink = uplink
	sessionRule.AuthSessAmbr.Downlink = downlink

	updated := 0
	for _, dataPath := range c.Tunnel.DataPathPool {
		if !dataPath.Activated {
			continue
		}
		for node := dataPath.FirstDPNode; node != nil; node = node.Next() {
			qerID, ok := c.AMBRQerMap[node.UPF.uuid]
			if !ok {
				continue
			}
			v, loaded := node.UPF.qerPool.Load(qerID)
			if !loaded {
				continue
			}
			qer := v.(*QER)
			qer.MBR = &pfcpType.MBR{ULMBR: ulKbps, DLMBR: dlKbps}
			qer.State = RULE_UPDATE
			updated++
		}
	}

	logger.PduSessLog.Infof("ApplySessionAMBR supi[%s] gpsi[%s]: UL=%s DL=%s (updated %d AMBR QER(s))",
		c.Supi, c.Gpsi, uplink, downlink, updated)
	if updated == 0 {
		return fmt.Errorf("no active AMBR QER found to update for supi[%s]", c.Supi)
	}
	return nil
}
