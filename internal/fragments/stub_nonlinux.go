//go:build !linux
// +build !linux

package fragments

import (
    "context"
    "github.com/phantom-fragment/phantom-fragment/pkg/types"
)

// Minimal stubs to satisfy package build on non-Linux platforms.
// The real implementations are Linux-only.

// WarmProcess is a placeholder for non-Linux builds.
type WarmProcess struct{}

// ZygoteSpawnerV3 is a placeholder for non-Linux builds.
type ZygoteSpawnerV3 struct{}

// ZygoteConfig is a placeholder config for non-Linux builds.
type ZygoteConfig struct{}

// NewZygoteSpawnerV3 returns a stub spawner on non-Linux.
func NewZygoteSpawnerV3(_ *ZygoteConfig) (*ZygoteSpawnerV3, error) { return &ZygoteSpawnerV3{}, nil }

// WarmupPool is a no-op on non-Linux builds.
func (z *ZygoteSpawnerV3) WarmupPool(_ string, _ int) error { return nil }

// SpawnFromPool returns a minimal container on non-Linux builds.
// It mirrors the linux signature and uses pkg/types.
func (z *ZygoteSpawnerV3) SpawnFromPool(_ context.Context, profile string, _ *types.SpawnRequest) (*types.Container, error) {
    return &types.Container{Profile: profile}, nil
}
