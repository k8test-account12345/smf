package sbi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) getOAMRoutes() []Route {
	return []Route{
		{
			Name:    "Index",
			Method:  http.MethodGet,
			Pattern: "/",
			APIFunc: func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "Service Available"})
			},
		},
		{
			Name:    "Get UE PDU Session Info",
			Method:  http.MethodGet,
			Pattern: "/ue-pdu-session-info/:smContextRef",
			APIFunc: s.HTTPGetUEPDUSessionInfo,
		},
		{
			Name:    "Get SMF Userplane Information",
			Method:  http.MethodGet,
			Pattern: "/user-plane-info/",
			APIFunc: s.HTTPGetSMFUserPlaneInfo,
		},
		{
			Name:    "List UE Sessions",
			Method:  http.MethodGet,
			Pattern: "/ue-sessions",
			APIFunc: s.HTTPListUESessions,
		},
		{
			Name:    "Release UE Session",
			Method:  http.MethodDelete,
			Pattern: "/ue-sessions/:ref",
			APIFunc: s.HTTPReleaseUESession,
		},
		{
			Name:    "Get UE Session AMBR",
			Method:  http.MethodGet,
			Pattern: "/ue-session-ambr/:gpsi",
			APIFunc: s.HTTPGetUESessionAMBR,
		},
		{
			Name:    "Set UE Session AMBR",
			Method:  http.MethodPut,
			Pattern: "/ue-session-ambr/:gpsi",
			APIFunc: s.HTTPSetUESessionAMBR,
		},
	}
}

func (s *Server) HTTPListUESessions(c *gin.Context) {
	s.Processor().HandleOAMListSessions(c)
}

func (s *Server) HTTPReleaseUESession(c *gin.Context) {
	s.Processor().HandleOAMReleaseSession(c, c.Params.ByName("ref"))
}

func (s *Server) HTTPGetUESessionAMBR(c *gin.Context) {
	s.Processor().HandleOAMGetSessionAMBR(c, c.Params.ByName("gpsi"))
}

func (s *Server) HTTPSetUESessionAMBR(c *gin.Context) {
	s.Processor().HandleOAMSetSessionAMBR(c, c.Params.ByName("gpsi"))
}

func (s *Server) HTTPGetUEPDUSessionInfo(c *gin.Context) {
	smContextRef := c.Params.ByName("smContextRef")

	s.Processor().HandleOAMGetUEPDUSessionInfo(c, smContextRef)
}

func (s *Server) HTTPGetSMFUserPlaneInfo(c *gin.Context) {
	s.Processor().HandleGetSMFUserPlaneInfo(c)
}
