// Package operator reconciles MatrixAgent custom resources against the agent
// service. A MatrixAgent declares one Matrix agent account; the operator creates
// or adopts the account, rotates its token before expiry or on request, and
// writes the current token into a Secret in the resource's own namespace.
//
// Authorization model: the operator only watches an explicit namespace
// allowlist, and an agent name can be claimed by exactly one MatrixAgent (the
// oldest). Accounts that exist without a MatrixAgent are only adopted when the
// resource sets spec.adoptExisting.
package operator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ksamaschke/matrix-agent-manager/internal/agents"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	Group     = "matrix-agent-manager.io"
	Version   = "v1alpha1"
	Resource  = "matrixagents"
	Finalizer = "matrix-agent-manager.io/finalizer"

	// GenerationAnnotation carries the token generation on the target Secret.
	GenerationAnnotation = "matrix-agent-manager.io/token-generation"
	partOfLabel          = "app.kubernetes.io/part-of"
	agentLabel           = "matrix-agent-manager.io/agent"

	PhaseReady    = "Ready"
	PhaseConflict = "Conflict"
	PhaseFailed   = "Failed"
)

var GVR = schema.GroupVersionResource{Group: Group, Version: Version, Resource: Resource}

// AgentService is the subset of agents.Service the operator drives.
type AgentService interface {
	Create(context.Context, agents.CreateRequest) (agents.Result, error)
	Rotate(context.Context, string) (agents.Result, error)
	Deactivate(context.Context, string) (agents.Result, error)
}

// Records reads persisted agent records including token material.
type Records interface {
	GetAgent(context.Context, string) (agents.SecretRecord, error)
}

type Config struct {
	Namespaces []string
	Interval   time.Duration
	// RotateAfter rotates an active token once it is older than this. Zero
	// disables age based rotation.
	RotateAfter          time.Duration
	HomeserverURL        string
	MatrixUserIDTemplate string
	DeviceIDTemplate     string
}

type Operator struct {
	dyn     dynamic.Interface
	kube    kubernetes.Interface
	service AgentService
	records Records
	config  Config
	now     func() time.Time
}

func New(dyn dynamic.Interface, kube kubernetes.Interface, service AgentService, records Records, config Config) (*Operator, error) {
	if dyn == nil || kube == nil || service == nil || records == nil {
		return nil, errors.New("operator requires Kubernetes clients, agent service and records")
	}
	if len(config.Namespaces) == 0 {
		return nil, errors.New("operator requires at least one watched namespace")
	}
	if config.Interval <= 0 {
		config.Interval = 30 * time.Second
	}
	if strings.Count(config.MatrixUserIDTemplate, "{localpart}") != 1 {
		return nil, errors.New("operator requires a Matrix user ID template with one {localpart}")
	}
	return &Operator{dyn: dyn, kube: kube, service: service, records: records, config: config, now: time.Now}, nil
}

// Run reconciles all MatrixAgents every interval until ctx ends.
func (o *Operator) Run(ctx context.Context) {
	slog.Info("matrix agent operator started", "namespaces", o.config.Namespaces, "interval", o.config.Interval.String())
	ticker := time.NewTicker(o.config.Interval)
	defer ticker.Stop()
	for {
		if err := o.ReconcileAll(ctx); err != nil {
			slog.Error("matrix agent reconcile pass failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type spec struct {
	AgentName      string   `json:"agentName"`
	DisplayName    string   `json:"displayName"`
	SecretName     string   `json:"secretName"`
	AdoptExisting  bool     `json:"adoptExisting"`
	DeletionPolicy string   `json:"deletionPolicy"`
	RotationToken  string   `json:"rotationToken"`
	RestartTargets []string `json:"restartDeployments"`
}

type status struct {
	Phase               string `json:"phase,omitempty"`
	Message             string `json:"message,omitempty"`
	ObservedGeneration  int64  `json:"observedGeneration,omitempty"`
	MatrixUserID        string `json:"matrixUserId,omitempty"`
	DeviceID            string `json:"deviceId,omitempty"`
	MASUserID           string `json:"masUserId,omitempty"`
	TokenGeneration     int    `json:"tokenGeneration,omitempty"`
	RotationToken       string `json:"rotationToken,omitempty"`
	LastRotationTime    string `json:"lastRotationTime,omitempty"`
	SecretName          string `json:"secretName,omitempty"`
	RestartedGeneration int    `json:"restartedGeneration,omitempty"`
}

func decode(obj *unstructured.Unstructured) (spec, status, error) {
	var s spec
	var st status
	raw, _ := json.Marshal(obj.Object["spec"])
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, st, fmt.Errorf("invalid spec: %w", err)
	}
	if obj.Object["status"] != nil {
		raw, _ = json.Marshal(obj.Object["status"])
		_ = json.Unmarshal(raw, &st)
	}
	if strings.TrimSpace(s.AgentName) == "" {
		s.AgentName = obj.GetName()
	}
	if s.DeletionPolicy == "" {
		s.DeletionPolicy = "Retain"
	}
	return s, st, nil
}

func (o *Operator) ReconcileAll(ctx context.Context) error {
	var all []*unstructured.Unstructured
	var listErrs []error
	for _, ns := range o.config.Namespaces {
		list, err := o.dyn.Resource(GVR).Namespace(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			listErrs = append(listErrs, fmt.Errorf("list MatrixAgents in %s: %w", ns, err))
			continue
		}
		for i := range list.Items {
			all = append(all, &list.Items[i])
		}
	}
	owners := claimOwners(all)
	errs := listErrs
	for _, obj := range all {
		if err := o.reconcile(ctx, obj, owners); err != nil {
			errs = append(errs, fmt.Errorf("%s/%s: %w", obj.GetNamespace(), obj.GetName(), err))
		}
	}
	return errors.Join(errs...)
}

// claimOwners maps each agent name to the oldest MatrixAgent claiming it.
func claimOwners(all []*unstructured.Unstructured) map[string]string {
	sorted := append([]*unstructured.Unstructured(nil), all...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ti, tj := sorted[i].GetCreationTimestamp(), sorted[j].GetCreationTimestamp()
		if !ti.Equal(&tj) {
			return ti.Before(&tj)
		}
		return key(sorted[i]) < key(sorted[j])
	})
	owners := map[string]string{}
	for _, obj := range sorted {
		if obj.GetDeletionTimestamp() != nil {
			continue
		}
		s, _, err := decode(obj)
		if err != nil {
			continue
		}
		if _, taken := owners[s.AgentName]; !taken {
			owners[s.AgentName] = key(obj)
		}
	}
	return owners
}

func key(obj *unstructured.Unstructured) string { return obj.GetNamespace() + "/" + obj.GetName() }

func (o *Operator) reconcile(ctx context.Context, obj *unstructured.Unstructured, owners map[string]string) error {
	s, st, err := decode(obj)
	if err != nil {
		return o.setStatus(ctx, obj, st, PhaseFailed, err.Error())
	}
	if obj.GetDeletionTimestamp() != nil {
		return o.finalize(ctx, obj, s, st)
	}
	if owner := owners[s.AgentName]; owner != key(obj) {
		return o.setStatus(ctx, obj, st, PhaseConflict, fmt.Sprintf("agent %q is already claimed by MatrixAgent %s", s.AgentName, owner))
	}
	if strings.TrimSpace(s.DisplayName) == "" || strings.TrimSpace(s.SecretName) == "" {
		return o.setStatus(ctx, obj, st, PhaseFailed, "spec.displayName and spec.secretName are required")
	}
	if s.DeletionPolicy != "Retain" && s.DeletionPolicy != "Deactivate" {
		return o.setStatus(ctx, obj, st, PhaseFailed, "spec.deletionPolicy must be Retain or Deactivate")
	}
	if !containsString(obj.GetFinalizers(), Finalizer) {
		obj.SetFinalizers(append(obj.GetFinalizers(), Finalizer))
		updated, err := o.dyn.Resource(GVR).Namespace(obj.GetNamespace()).Update(ctx, obj, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("add finalizer: %w", err)
		}
		obj = updated
	}

	record, err := o.records.GetAgent(ctx, s.AgentName)
	switch {
	case errors.Is(err, agents.ErrNotFound):
		if _, err := o.service.Create(ctx, agents.CreateRequest{AgentName: s.AgentName, DisplayName: s.DisplayName}); err != nil {
			return o.setStatus(ctx, obj, st, PhaseFailed, "create agent: "+err.Error())
		}
		slog.Info("matrix agent created", "agent", s.AgentName, "resource", key(obj))
		st.RotationToken = s.RotationToken
	case err != nil:
		return o.setStatus(ctx, obj, st, PhaseFailed, "read agent: "+err.Error())
	default:
		if st.MASUserID == "" && !s.AdoptExisting {
			return o.setStatus(ctx, obj, st, PhaseConflict, fmt.Sprintf("agent %q exists outside this resource; set spec.adoptExisting to take it over", s.AgentName))
		}
		if st.MASUserID != "" && st.MASUserID != record.MASUserID {
			return o.setStatus(ctx, obj, st, PhaseConflict, "agent was recreated outside this resource")
		}
		reason := ""
		switch {
		case record.Status == agents.StatusDeactivated:
			return o.setStatus(ctx, obj, st, PhaseFailed, "agent is deactivated; reactivate it in the dashboard or remove the account")
		case record.Status != agents.StatusActive:
			reason = "token revoked"
		case st.MASUserID != "" && s.RotationToken != st.RotationToken:
			reason = "rotation requested"
		case o.config.RotateAfter > 0 && o.now().Sub(record.UpdatedAt) > o.config.RotateAfter:
			reason = "token age"
		}
		if reason != "" {
			if _, err := o.service.Rotate(ctx, s.AgentName); err != nil {
				return o.setStatus(ctx, obj, st, PhaseFailed, "rotate agent token: "+err.Error())
			}
			slog.Info("matrix agent token rotated", "agent", s.AgentName, "reason", reason, "resource", key(obj))
		}
		st.RotationToken = s.RotationToken
	}

	record, err = o.records.GetAgent(ctx, s.AgentName)
	if err != nil {
		return o.setStatus(ctx, obj, st, PhaseFailed, "read agent after reconcile: "+err.Error())
	}
	userID := strings.Replace(o.config.MatrixUserIDTemplate, "{localpart}", s.AgentName, 1)
	deviceID := strings.Replace(o.config.DeviceIDTemplate, "{agent_name}", s.AgentName, 1)
	changed, err := o.writeSecret(ctx, obj, s, record, userID, deviceID)
	if err != nil {
		return o.setStatus(ctx, obj, st, PhaseFailed, err.Error())
	}
	// Restart consumers when the token changed, or when a previous pass wrote
	// the Secret but did not get to restart them.
	if changed || (st.RestartedGeneration != 0 && st.RestartedGeneration != record.Generation) {
		for _, name := range s.RestartTargets {
			if err := o.restartDeployment(ctx, obj.GetNamespace(), name); err != nil {
				return o.setStatus(ctx, obj, st, PhaseFailed, err.Error())
			}
		}
	}
	st.RestartedGeneration = record.Generation
	st.MatrixUserID, st.DeviceID, st.MASUserID = userID, deviceID, record.MASUserID
	st.TokenGeneration = record.Generation
	st.LastRotationTime = record.UpdatedAt.UTC().Format(time.RFC3339)
	st.SecretName = s.SecretName
	return o.setStatus(ctx, obj, st, PhaseReady, "token is current")
}

// writeSecret creates or updates the token Secret and reports whether its
// content changed.
func (o *Operator) writeSecret(ctx context.Context, obj *unstructured.Unstructured, s spec, record agents.SecretRecord, userID, deviceID string) (bool, error) {
	secrets := o.kube.CoreV1().Secrets(obj.GetNamespace())
	desired := map[string][]byte{
		"access-token": []byte(record.AccessToken),
		"user-id":      []byte(userID),
		"device-id":    []byte(deviceID),
	}
	if o.config.HomeserverURL != "" {
		desired["homeserver"] = []byte(o.config.HomeserverURL)
	}
	controller := true
	ownerRef := metav1.OwnerReference{APIVersion: Group + "/" + Version, Kind: "MatrixAgent", Name: obj.GetName(), UID: obj.GetUID(), Controller: &controller}
	generation := strconv.Itoa(record.Generation)

	current, err := secrets.Get(ctx, s.SecretName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = secrets.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: s.SecretName, Namespace: obj.GetNamespace(),
				Labels:          map[string]string{partOfLabel: "matrix-agent-manager", agentLabel: s.AgentName},
				Annotations:     map[string]string{GenerationAnnotation: generation},
				OwnerReferences: []metav1.OwnerReference{ownerRef},
			},
			Type: corev1.SecretTypeOpaque,
			Data: desired,
		}, metav1.CreateOptions{})
		if err != nil {
			return false, fmt.Errorf("create token secret: %w", err)
		}
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read token secret: %w", err)
	}
	owned := false
	for _, ref := range current.OwnerReferences {
		if ref.UID == obj.GetUID() {
			owned = true
		}
	}
	if !owned && !s.AdoptExisting {
		return false, fmt.Errorf("secret %s exists and is not owned by this MatrixAgent; set spec.adoptExisting to take it over", s.SecretName)
	}
	changed := !owned || current.Annotations[GenerationAnnotation] != generation || current.Labels[agentLabel] != s.AgentName
	for k, v := range desired {
		if string(current.Data[k]) != string(v) {
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	// Adopting a Secret that already holds the current token is not a change
	// for the consumers.
	tokenChanged := string(current.Data["access-token"]) != record.AccessToken
	if current.Labels == nil {
		current.Labels = map[string]string{}
	}
	if current.Annotations == nil {
		current.Annotations = map[string]string{}
	}
	current.Labels[partOfLabel] = "matrix-agent-manager"
	current.Labels[agentLabel] = s.AgentName
	current.Annotations[GenerationAnnotation] = generation
	if !owned {
		current.OwnerReferences = append(current.OwnerReferences, ownerRef)
	}
	current.Data = desired
	if _, err := secrets.Update(ctx, current, metav1.UpdateOptions{}); err != nil {
		return false, fmt.Errorf("update token secret: %w", err)
	}
	return tokenChanged, nil
}

// restartDeployment deletes the Deployment's pods so they start with the new
// token. The Deployment object stays untouched, so GitOps tools see no drift.
func (o *Operator) restartDeployment(ctx context.Context, namespace, name string) error {
	current, err := o.kube.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil // not deployed yet; it starts with the current token
	}
	if err != nil {
		return fmt.Errorf("read restart target %s: %w", name, err)
	}
	selector, err := metav1.LabelSelectorAsSelector(current.Spec.Selector)
	if err != nil || selector.Empty() {
		return fmt.Errorf("restart target %s has no usable selector", name)
	}
	if err := o.kube.CoreV1().Pods(namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: selector.String()}); err != nil {
		return fmt.Errorf("restart %s: %w", name, err)
	}
	slog.Info("restarted token consumer", "namespace", namespace, "deployment", name)
	return nil
}

func (o *Operator) finalize(ctx context.Context, obj *unstructured.Unstructured, s spec, st status) error {
	if !containsString(obj.GetFinalizers(), Finalizer) {
		return nil
	}
	if s.DeletionPolicy == "Deactivate" && st.MASUserID != "" {
		if _, err := o.service.Deactivate(ctx, s.AgentName); err != nil && !errors.Is(err, agents.ErrNotFound) {
			return o.setStatus(ctx, obj, st, PhaseFailed, "deactivate agent: "+err.Error())
		}
		slog.Info("matrix agent deactivated", "agent", s.AgentName, "resource", key(obj))
	}
	kept := make([]string, 0)
	for _, f := range obj.GetFinalizers() {
		if f != Finalizer {
			kept = append(kept, f)
		}
	}
	obj.SetFinalizers(kept)
	_, err := o.dyn.Resource(GVR).Namespace(obj.GetNamespace()).Update(ctx, obj, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (o *Operator) setStatus(ctx context.Context, obj *unstructured.Unstructured, st status, phase, message string) error {
	st.Phase, st.Message, st.ObservedGeneration = phase, message, obj.GetGeneration()
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&st)
	if err != nil {
		return fmt.Errorf("encode status: %w", err)
	}
	raw, _ := json.Marshal(m)
	old, _ := json.Marshal(obj.Object["status"])
	if string(old) == string(raw) {
		return phaseError(phase, message)
	}
	obj.Object["status"] = m
	if _, err := o.dyn.Resource(GVR).Namespace(obj.GetNamespace()).UpdateStatus(ctx, obj, metav1.UpdateOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("update status: %w", err)
	}
	return phaseError(phase, message)
}

func phaseError(phase, message string) error {
	if phase == PhaseReady {
		return nil
	}
	return fmt.Errorf("%s: %s", phase, message)
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
