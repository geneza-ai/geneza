package controller

import (
	"context"
	"fmt"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// rolloutStatusResp assembles the observable status of a product's rollout,
// including the live wave member/health counts and remaining soak.
func (s *Server) rolloutStatusResp(product string) (*genezav1.RolloutStatusResponse, error) {
	r, err := s.loadRollout(product)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load rollout: %v", err)
	}
	resp := &genezav1.RolloutStatusResponse{
		Product:    productLabel(product),
		AutoUpdate: s.autoUpdateEnabled(product),
	}
	if r == nil {
		return resp, nil // present=false
	}
	total, healthy := s.rolloutHealthCounts(r)
	waves := make([]int32, len(r.Waves))
	for i, w := range r.Waves {
		waves[i] = int32(w)
	}
	soakRemaining := r.SoakSeconds
	if r.HealthySince > 0 {
		if rem := r.SoakSeconds - (time.Now().Unix() - r.HealthySince); rem > 0 {
			soakRemaining = rem
		} else {
			soakRemaining = 0
		}
	}
	resp.Present = true
	resp.Target = r.Target
	resp.Waves = waves
	resp.WaveIdx = int32(r.WaveIdx)
	resp.State = string(r.State)
	resp.Trigger = string(r.Trigger)
	resp.EligibleCount = int32(len(r.Eligible))
	resp.WaveMembers = int32(total)
	resp.WaveHealthy = int32(healthy)
	resp.SoakSeconds = r.SoakSeconds
	resp.SoakRemainingSeconds = soakRemaining
	resp.WaveTimeoutSeconds = r.WaveTimeoutSeconds
	resp.Blockers = r.Blockers
	resp.HaltReason = r.HaltReason
	return resp, nil
}

func (a *clusterAPIService) StartRollout(ctx context.Context, req *genezav1.StartRolloutRequest) (*genezav1.RolloutStatusResponse, error) {
	waves := make([]int, len(req.GetWaves()))
	for i, w := range req.GetWaves() {
		waves[i] = int(w)
	}
	if _, err := a.s.startRollout(req.GetProduct(), req.GetVersion(), waves, req.GetSoakSeconds(), req.GetWaveTimeoutSeconds(), TriggerAdmin, adminActor(ctx)); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return a.s.rolloutStatusResp(req.GetProduct())
}

func (a *clusterAPIService) GetRolloutStatus(ctx context.Context, req *genezav1.RolloutControlRequest) (*genezav1.RolloutStatusResponse, error) {
	return a.s.rolloutStatusResp(req.GetProduct())
}

func (a *clusterAPIService) PauseRollout(ctx context.Context, req *genezav1.RolloutControlRequest) (*genezav1.RolloutStatusResponse, error) {
	if _, err := a.s.pauseRollout(req.GetProduct(), adminActor(ctx)); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return a.s.rolloutStatusResp(req.GetProduct())
}

func (a *clusterAPIService) ResumeRollout(ctx context.Context, req *genezav1.RolloutControlRequest) (*genezav1.RolloutStatusResponse, error) {
	if _, err := a.s.resumeRollout(req.GetProduct(), adminActor(ctx)); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return a.s.rolloutStatusResp(req.GetProduct())
}

func (a *clusterAPIService) AbortRollout(ctx context.Context, req *genezav1.RolloutControlRequest) (*genezav1.RolloutStatusResponse, error) {
	if _, err := a.s.abortRollout(req.GetProduct(), adminActor(ctx)); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return a.s.rolloutStatusResp(req.GetProduct())
}

func (a *clusterAPIService) SetAutoUpdate(ctx context.Context, req *genezav1.SetAutoUpdateRequest) (*genezav1.Empty, error) {
	if err := a.s.setAutoUpdate(req.GetProduct(), req.GetEnabled()); err != nil {
		return nil, status.Errorf(codes.Internal, "set auto-update: %v", err)
	}
	_ = a.s.audit.Append("rollout_auto_update", adminActor(ctx), "", "", map[string]string{
		"product": productLabel(req.GetProduct()), "enabled": fmt.Sprint(req.GetEnabled()),
	})
	return &genezav1.Empty{}, nil
}
