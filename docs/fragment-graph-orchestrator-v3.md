# Fragment Graph Orchestrator V3 - Design Specification

## Overview

The **Fragment Graph Orchestrator** is the intelligent "brain" of Phantom Fragment V3, providing PSI-aware scheduling, NUMA-optimized placement, and ML-enhanced resource management. It coordinates all fragments to deliver consistent performance under varying loads.

## Architecture Design

### Core Components

```go
type FragmentGraphOrchestrator struct {
    // Core scheduling components
    psiMonitor        *PSIMonitorV3
    numaTopology      *NUMATopology
    loadBalancer      *IntelligentLoadBalancer
    
    // Fragment coordination
    fragmentRegistry  *FragmentRegistry
    fragmentPools     map[string]*FragmentPool
    dependencyGraph   *FragmentDependencyGraph
    
    // ML-enhanced optimization
    mlPredictor       *ResourcePredictor
    behaviorAnalyzer  *WorkloadAnalyzer
    adaptiveScaler    *AdaptiveScaler
    
    // Performance optimization
    performanceTracker *PerformanceTracker
    congestionManager  *CongestionManager
    resourceOptimizer  *ResourceOptimizer
    
    // Health and monitoring
    healthMonitor     *HealthMonitor
    metricsCollector  *OrchestratorMetrics
    alertManager      *AlertManager
    
    // Configuration
    config            *OrchestratorConfig
    policies          *SchedulingPolicies
}

// Fragment pool management
type FragmentPool struct {
    FragmentType     FragmentType
    Profile          string
    ActiveFragments  []*ActiveFragment
    WarmFragments    []*WarmFragment
    
    // Pool configuration
    TargetSize       int
    MaxSize          int
    MinSize          int
    ScalePolicy      *ScalingPolicy
    
    // Performance tracking
    Utilization      float64
    AverageLatency   time.Duration
    ThroughputRPS    float64
    ErrorRate        float64
    
    // NUMA affinity
    PreferredNUMANodes []int
    CPUAffinity        []int
}

// Active fragment instance
type ActiveFragment struct {
    ID               string
    Type             FragmentType
    Profile          string
    NUMANode         int
    CPUAffinity      []int
    
    // State tracking
    State            FragmentState
    LastUsed         time.Time
    RequestCount     int64
    ProcessingTime   time.Duration
    
    // Resource usage
    MemoryUsage      int64
    CPUUsage         float64
    IOUtilization    float64
    
    // Health status
    HealthScore      float64
    ErrorCount       int64
    LastError        error
}
```

## PSI-Aware Scheduling

### Linux Pressure Stall Information Integration

```go
type PSIMonitorV3 struct {
    // PSI data sources
    cpuPSI           *PSISource
    memoryPSI        *PSISource
    ioPSI            *PSISource
    
    // Per-NUMA node monitoring
    numaPSI          map[int]*NUMAPSIData
    
    // Historical data
    history          *PSIHistory
    trends           *PSITrendAnalyzer
    
    // Thresholds and policies
    thresholds       *PSIThresholds
    responseActions  map[PSILevel][]ResponseAction
    
    // Real-time monitoring
    updateInterval   time.Duration
    alertThreshold   time.Duration
}

type PSIData struct {
    // Current pressure readings (0.0 to 1.0)
    Avg10s          float64  // 10-second average
    Avg60s          float64  // 60-second average
    Avg300s         float64  // 5-minute average
    Total           uint64   // Total stall time in microseconds
    
    // Trend analysis
    Trend           PSITrend
    Velocity        float64  // Rate of change
    Prediction      float64  // Predicted pressure in next period
}

type PSIThresholds struct {
    // CPU pressure thresholds
    CPULow          float64  // 0.3 - Normal operation
    CPUMedium       float64  // 0.6 - Start scaling
    CPUHigh         float64  // 0.8 - Aggressive scaling
    CPUCritical     float64  // 0.9 - Emergency measures
    
    // Memory pressure thresholds
    MemoryLow       float64  // 0.2 - Normal operation
    MemoryMedium    float64  // 0.5 - Start reclaiming
    MemoryHigh      float64  // 0.7 - Aggressive reclaiming
    MemoryCritical  float64  // 0.85 - OOM prevention
    
    // I/O pressure thresholds
    IOLow           float64  // 0.4 - Normal operation
    IOMedium        float64  // 0.6 - Optimize I/O patterns
    IOHigh          float64  // 0.8 - Throttle I/O intensive tasks
    IOCritical      float64  // 0.9 - Emergency I/O management
}

// PSI-aware container placement
func (o *FragmentGraphOrchestrator) ScheduleContainer(
    request *SchedulingRequest,
) (*SchedulingDecision, error) {
    
    start := time.Now()
    
    // Phase 1: Get current system pressure
    systemPressure := o.psiMonitor.GetCurrentPressure()
    
    // Phase 2: Check if scheduling should be delayed
    if o.shouldDeferScheduling(systemPressure, request) {
        return &SchedulingDecision{
            Action:    SchedulingActionDefer,
            Reason:    "High system pressure",
            RetryAfter: o.calculateRetryDelay(systemPressure),
        }, nil
    }
    
    // Phase 3: Select optimal NUMA node
    numaNode, err := o.selectOptimalNUMANode(request, systemPressure)
    if err != nil {
        return nil, fmt.Errorf("NUMA node selection failed: %w", err)
    }
    
    // Phase 4: Select fragment pool
    pool, err := o.selectFragmentPool(request, numaNode)
    if err != nil {
        return nil, fmt.Errorf("fragment pool selection failed: %w", err)
    }
    
    // Phase 5: Get or create fragment
    fragment, err := o.acquireFragment(pool, request)
    if err != nil {
        return nil, fmt.Errorf("fragment acquisition failed: %w", err)
    }
    
    decision := &SchedulingDecision{
        Action:        SchedulingActionSchedule,
        Fragment:      fragment,
        NUMANode:      numaNode,
        Pool:          pool,
        SchedulingTime: time.Since(start),
        Confidence:    o.calculateConfidence(systemPressure, fragment),
    }
    
    // Record scheduling metrics
    o.metricsCollector.RecordScheduling(decision)
    
    return decision, nil
}

// Determine if scheduling should be deferred due to pressure
func (o *FragmentGraphOrchestrator) shouldDeferScheduling(
    pressure *SystemPressure,
    request *SchedulingRequest,
) bool {
    
    // Check CPU pressure
    if pressure.CPU >= o.psiMonitor.thresholds.CPUHigh {
        return true
    }
    
    // Check memory pressure
    if pressure.Memory >= o.psiMonitor.thresholds.MemoryHigh {
        return true
    }
    
    // Check I/O pressure for I/O intensive workloads
    if request.Profile.IOIntensive && pressure.IO >= o.psiMonitor.thresholds.IOHigh {
        return true
    }
    
    // Allow scheduling for high priority requests even under pressure
    if request.Priority >= PriorityHigh {
        return false
    }
    
    return false
}
```

### NUMA-Aware Placement

```go
type NUMATopology struct {
    Nodes           map[int]*NUMANode
    NodeCount       int
    CPUMap          map[int]int  // CPU to NUMA node mapping
    MemoryMap       map[int]int  // Memory bank to NUMA node mapping
    
    // Performance characteristics
    LocalLatency    map[int]time.Duration      // Local memory access
    RemoteLatency   map[int]map[int]time.Duration // Remote access matrix
    Bandwidth       map[int]int64              // Memory bandwidth per node
    
    // Current utilization
    CPUUtilization  map[int]float64
    MemoryUsage     map[int]int64
    
    // Fragment placement tracking
    FragmentMap     map[string]int  // Fragment ID to NUMA node
}

type NUMANode struct {
    ID              int
    CPUs            []int
    MemorySize      int64
    MemoryAvailable int64
    
    // Current load
    CPULoad         float64
    MemoryLoad      float64
    
    // Fragment affinity
    PreferredProfiles []string
    ActiveFragments   []*ActiveFragment
    
    // Performance metrics
    LocalAccessLatency  time.Duration
    RemoteAccessRatio   float64
}

// Select optimal NUMA node for container placement
func (o *FragmentGraphOrchestrator) selectOptimalNUMANode(
    request *SchedulingRequest,
    pressure *SystemPressure,
) (int, error) {
    
    topology := o.numaTopology
    candidates := make([]*NUMACandidate, 0, topology.NodeCount)
    
    // Phase 1: Evaluate each NUMA node
    for nodeID, node := range topology.Nodes {
        candidate := &NUMACandidate{
            NodeID: nodeID,
            Node:   node,
        }
        
        // Calculate placement score
        candidate.Score = o.calculateNUMAScore(node, request, pressure)
        
        // Check placement constraints
        if o.checkNUMAConstraints(node, request) {
            candidates = append(candidates, candidate)
        }
    }
    
    if len(candidates) == 0 {
        return -1, fmt.Errorf("no suitable NUMA nodes available")
    }
    
    // Phase 2: Sort by score (higher is better)
    sort.Slice(candidates, func(i, j int) bool {
        return candidates[i].Score > candidates[j].Score
    })
    
    // Phase 3: Select best candidate with some randomization to avoid hotspots
    selectedIndex := o.selectWithJitter(candidates)
    selected := candidates[selectedIndex]
    
    o.metricsCollector.RecordNUMAPlacement(selected.NodeID, selected.Score)
    
    return selected.NodeID, nil
}

// Calculate NUMA placement score
func (o *FragmentGraphOrchestrator) calculateNUMAScore(
    node *NUMANode,
    request *SchedulingRequest,
    pressure *SystemPressure,
) float64 {
    
    score := 0.0
    
    // Factor 1: Resource availability (40% weight)
    cpuAvailability := 1.0 - node.CPULoad
    memoryAvailability := float64(node.MemoryAvailable) / float64(node.MemorySize)
    resourceScore := (cpuAvailability*0.6 + memoryAvailability*0.4) * 0.4
    score += resourceScore
    
    // Factor 2: Memory locality (30% weight)
    localityScore := o.calculateLocalityScore(node, request) * 0.3
    score += localityScore
    
    // Factor 3: Fragment affinity (20% weight)
    affinityScore := o.calculateAffinityScore(node, request) * 0.2
    score += affinityScore
    
    // Factor 4: Load balancing (10% weight)
    balanceScore := o.calculateBalanceScore(node) * 0.1
    score += balanceScore
    
    // Penalty for high pressure nodes
    if pressure.PerNUMANode != nil {
        if numaPressure, exists := pressure.PerNUMANode[node.ID]; exists {
            pressurePenalty := (numaPressure.CPU + numaPressure.Memory) / 2.0
            score *= (1.0 - pressurePenalty*0.3) // Up to 30% penalty
        }
    }
    
    return score
}
```

## ML-Enhanced Resource Prediction

```go
type ResourcePredictor struct {
    // ML models for different prediction tasks
    demandModel      *DemandPredictionModel
    scaleModel       *ScalingPredictionModel
    performanceModel *PerformancePredictionModel
    
    // Training data
    historicalData   *HistoricalDataStore
    featureExtractor *FeatureExtractor
    
    // Model configuration
    predictionWindow time.Duration
    retrainInterval  time.Duration
    modelAccuracy    float64
    
    // Real-time features
    currentMetrics   *MetricsSnapshot
    workloadPattern  *WorkloadPattern
}

type DemandPrediction struct {
    Profile         string
    PredictedDemand float64      // Expected requests per second
    Confidence      float64      // Prediction confidence (0.0-1.0)
    TimeHorizon     time.Duration // How far ahead this prediction is valid
    
    // Resource requirements
    ExpectedCPU     float64
    ExpectedMemory  int64
    ExpectedIO      float64
    
    // Scaling recommendations
    RecommendedPoolSize int
    ScaleUpProbability  float64
    ScaleDownProbability float64
}

// ML-based demand prediction
func (rp *ResourcePredictor) PredictDemand(
    profile string,
    timeHorizon time.Duration,
) (*DemandPrediction, error) {
    
    // Phase 1: Extract features from historical data
    features, err := rp.featureExtractor.ExtractFeatures(profile, timeHorizon)
    if err != nil {
        return nil, fmt.Errorf("feature extraction failed: %w", err)
    }
    
    // Phase 2: Run demand prediction model
    demandOutput, err := rp.demandModel.Predict(features)
    if err != nil {
        return nil, fmt.Errorf("demand prediction failed: %w", err)
    }
    
    // Phase 3: Run scaling prediction model
    scaleOutput, err := rp.scaleModel.Predict(features)
    if err != nil {
        return nil, fmt.Errorf("scaling prediction failed: %w", err)
    }
    
    // Phase 4: Combine predictions
    prediction := &DemandPrediction{
        Profile:              profile,
        PredictedDemand:      demandOutput.RequestsPerSecond,
        Confidence:           demandOutput.Confidence,
        TimeHorizon:          timeHorizon,
        ExpectedCPU:          demandOutput.CPUUsage,
        ExpectedMemory:       int64(demandOutput.MemoryUsage),
        ExpectedIO:           demandOutput.IOUsage,
        RecommendedPoolSize:  int(scaleOutput.OptimalPoolSize),
        ScaleUpProbability:   scaleOutput.ScaleUpProbability,
        ScaleDownProbability: scaleOutput.ScaleDownProbability,
    }
    
    // Phase 5: Apply business logic constraints
    prediction = rp.applyConstraints(prediction)
    
    return prediction, nil
}

// Adaptive pool scaling based on ML predictions
func (o *FragmentGraphOrchestrator) ManagePoolScaling() {
    ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            o.performPoolScalingCycle()
        case <-o.shutdown:
            return
        }
    }
}

func (o *FragmentGraphOrchestrator) performPoolScalingCycle() {
    for profile, pool := range o.fragmentPools {
        // Get ML prediction for next 5 minutes
        prediction, err := o.mlPredictor.PredictDemand(profile, 5*time.Minute)
        if err != nil {
            log.Errorf("Prediction failed for profile %s: %v", profile, err)
            continue
        }
        
        // Get current system pressure
        pressure := o.psiMonitor.GetCurrentPressure()
        
        // Make scaling decision
        decision := o.makeScalingDecision(pool, prediction, pressure)
        
        // Execute scaling action
        if decision.Action != ScalingActionNone {
            o.executeScalingAction(pool, decision)
        }
    }
}

type ScalingDecision struct {
    Action       ScalingAction
    TargetSize   int
    Confidence   float64
    Reason       string
    Urgency      ScalingUrgency
}

func (o *FragmentGraphOrchestrator) makeScalingDecision(
    pool *FragmentPool,
    prediction *DemandPrediction,
    pressure *SystemPressure,
) *ScalingDecision {
    
    currentSize := len(pool.ActiveFragments) + len(pool.WarmFragments)
    recommendedSize := prediction.RecommendedPoolSize
    
    // Apply pressure-based adjustments
    if pressure.CPU > o.psiMonitor.thresholds.CPUMedium {
        // Reduce scaling under CPU pressure
        recommendedSize = min(recommendedSize, currentSize)
    }
    
    if pressure.Memory > o.psiMonitor.thresholds.MemoryMedium {
        // Reduce scaling under memory pressure
        recommendedSize = min(recommendedSize, currentSize-1)
    }
    
    // Determine action
    var action ScalingAction
    var urgency ScalingUrgency
    var reason string
    
    sizeDiff := recommendedSize - currentSize
    
    if sizeDiff > 0 {
        action = ScalingActionScaleUp
        urgency = o.calculateScaleUpUrgency(prediction, pressure)
        reason = fmt.Sprintf("ML predicted demand increase: %d -> %d", currentSize, recommendedSize)
    } else if sizeDiff < 0 {
        action = ScalingActionScaleDown
        urgency = ScalingUrgencyLow // Scale down is usually not urgent
        reason = fmt.Sprintf("ML predicted demand decrease: %d -> %d", currentSize, recommendedSize)
    } else {
        action = ScalingActionNone
        reason = "Pool size is optimal"
    }
    
    return &ScalingDecision{
        Action:     action,
        TargetSize: recommendedSize,
        Confidence: prediction.Confidence,
        Reason:     reason,
        Urgency:    urgency,
    }
}
```

## Performance Optimization

### Congestion Management

```go
type CongestionManager struct {
    // Congestion detection
    congestionDetector *CongestionDetector
    trafficShaper      *TrafficShaper
    
    // Admission control
    admissionController *AdmissionController
    requestQueue        *PriorityQueue
    
    // Load shedding
    loadShedder        *LoadShedder
    circuitBreaker     *CircuitBreaker
    
    // Metrics
    metrics            *CongestionMetrics
}

// Intelligent admission control
func (cm *CongestionManager) ShouldAdmitRequest(
    request *SchedulingRequest,
    currentLoad *SystemLoad,
) (*AdmissionDecision, error) {
    
    // Phase 1: Check system capacity
    if cm.isSystemOverloaded(currentLoad) {
        // Apply load shedding policies
        if cm.shouldShedRequest(request, currentLoad) {
            return &AdmissionDecision{
                Admit:  false,
                Reason: "System overloaded - load shedding active",
                RetryAfter: cm.calculateRetryDelay(currentLoad),
            }, nil
        }
    }
    
    // Phase 2: Check resource availability
    resourceAvailable := cm.checkResourceAvailability(request)
    if !resourceAvailable {
        return &AdmissionDecision{
            Admit:  false,
            Reason: "Insufficient resources",
            RetryAfter: 5 * time.Second,
        }, nil
    }
    
    // Phase 3: Apply traffic shaping
    if cm.trafficShaper.ShouldThrottle(request) {
        return &AdmissionDecision{
            Admit:  true,
            Throttle: true,
            Delay:  cm.trafficShaper.CalculateDelay(request),
            Reason: "Traffic shaping applied",
        }, nil
    }
    
    // Admit request
    return &AdmissionDecision{
        Admit:  true,
        Reason: "Normal admission",
    }, nil
}

// Dynamic load shedding
func (cm *CongestionManager) shouldShedRequest(
    request *SchedulingRequest,
    load *SystemLoad,
) bool {
    
    // Never shed high priority requests
    if request.Priority >= PriorityHigh {
        return false
    }
    
    // Calculate load shedding probability based on system load
    loadFactor := (load.CPU + load.Memory + load.IO) / 3.0
    sheddingProbability := cm.calculateSheddingProbability(loadFactor)
    
    // Random shedding with bias towards lower priority requests
    random := rand.Float64()
    priorityBonus := float64(request.Priority) * 0.1
    
    return random < (sheddingProbability - priorityBonus)
}
```

## Health Monitoring & Self-Healing

```go
type HealthMonitor struct {
    // Health checkers
    fragmentHealth   map[string]*FragmentHealthChecker
    systemHealth     *SystemHealthChecker
    networkHealth    *NetworkHealthChecker
    
    // Recovery mechanisms
    selfHealing      *SelfHealingEngine
    failureDetector  *FailureDetector
    recoveryManager  *RecoveryManager
    
    // Health metrics
    healthScores     map[string]float64
    unhealthyFragments map[string]*UnhealthyFragment
    
    // Configuration
    healthCheckInterval time.Duration
    unhealthyThreshold  float64
    recoveryTimeout     time.Duration
}

// Continuous health monitoring
func (hm *HealthMonitor) MonitorHealth() {
    ticker := time.NewTicker(hm.healthCheckInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            hm.performHealthCheck()
        case <-hm.shutdown:
            return
        }
    }
}

func (hm *HealthMonitor) performHealthCheck() {
    // Check all fragment pools
    for profile, pool := range hm.orchestrator.fragmentPools {
        healthScore := hm.checkPoolHealth(pool)
        hm.healthScores[profile] = healthScore
        
        if healthScore < hm.unhealthyThreshold {
            hm.handleUnhealthyPool(profile, pool, healthScore)
        }
    }
    
    // Check system health
    systemHealth := hm.systemHealth.CheckHealth()
    if systemHealth.Score < hm.unhealthyThreshold {
        hm.handleSystemHealthIssue(systemHealth)
    }
}

// Self-healing mechanisms
func (hm *HealthMonitor) handleUnhealthyPool(
    profile string,
    pool *FragmentPool,
    healthScore float64,
) {
    
    unhealthy := &UnhealthyFragment{
        Profile:      profile,
        Pool:         pool,
        HealthScore:  healthScore,
        DetectedAt:   time.Now(),
        Symptoms:     hm.analyzeSymptoms(pool),
    }
    
    hm.unhealthyFragments[profile] = unhealthy
    
    // Determine recovery strategy
    strategy := hm.determineRecoveryStrategy(unhealthy)
    
    // Execute recovery
    go func() {
        if err := hm.selfHealing.ExecuteRecovery(strategy); err != nil {
            log.Errorf("Recovery failed for profile %s: %v", profile, err)
            hm.escalateHealthIssue(unhealthy, err)
        }
    }()
}

type RecoveryStrategy struct {
    Type        RecoveryType
    Actions     []RecoveryAction
    Timeout     time.Duration
    Rollback    bool
}

type RecoveryType int

const (
    RecoveryTypeRestart RecoveryType = iota
    RecoveryTypeRescale
    RecoveryTypeReplace
    RecoveryTypeDrain
    RecoveryTypeFailover
)

// Execute recovery actions
func (she *SelfHealingEngine) ExecuteRecovery(
    strategy *RecoveryStrategy,
) error {
    
    ctx, cancel := context.WithTimeout(context.Background(), strategy.Timeout)
    defer cancel()
    
    for _, action := range strategy.Actions {
        if err := she.executeRecoveryAction(ctx, action); err != nil {
            if strategy.Rollback {
                she.rollbackRecovery(strategy, action)
            }
            return fmt.Errorf("recovery action failed: %w", err)
        }
    }
    
    return nil
}
```

## Implementation Plan

### Phase 1: Core Orchestration Infrastructure (Week 1-2)
- [ ] Implement FragmentGraphOrchestrator structure
- [ ] PSI monitoring integration
- [ ] Basic NUMA topology detection
- [ ] Fragment registry and pool management

### Phase 2: Intelligent Scheduling (Week 2-3)
- [ ] PSI-aware scheduling algorithms
- [ ] NUMA-aware placement logic
- [ ] Resource prediction framework
- [ ] Load balancing mechanisms

### Phase 3: ML Enhancement (Week 3-4)
- [ ] ML model integration for demand prediction
- [ ] Adaptive scaling algorithms
- [ ] Performance optimization engine
- [ ] Congestion management system

### Phase 4: Health & Self-Healing (Week 4)
- [ ] Health monitoring system
- [ ] Self-healing mechanisms
- [ ] Failure detection and recovery
- [ ] Comprehensive testing and validation

## Success Criteria

### Performance Targets
- [ ] **Scheduling Latency**: <5ms scheduling decision time
- [ ] **NUMA Efficiency**: >90% local memory access ratio
- [ ] **Prediction Accuracy**: >85% demand prediction accuracy
- [ ] **Resource Utilization**: >80% average resource utilization
- [ ] **Load Balancing**: <10% variance in node utilization

### Reliability Metrics
- [ ] **Health Detection**: <30s mean time to detect health issues
- [ ] **Recovery Time**: <60s mean time to recovery
- [ ] **Availability**: >99.9% orchestrator availability
- [ ] **Self-Healing**: >95% automatic recovery success rate

### Scalability Validation
- [ ] Support for 1000+ concurrent containers
- [ ] Linear scaling with system resources
- [ ] Graceful degradation under extreme load
- [ ] Cross-platform performance consistency

The Fragment Graph Orchestrator provides the intelligent coordination needed to achieve Phantom Fragment V3's ambitious performance and reliability targets while maintaining optimal resource utilization across diverse workloads.