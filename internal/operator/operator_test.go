package operator

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ksamaschke/matrix-agent-manager/internal/agents"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const ns = "tenant-a"

// fakeService keeps agent records in memory and mimics create/rotate/deactivate.
type fakeService struct {
	records  map[string]agents.SecretRecord
	creates  int
	rotates  int
	deacts   int
	now      time.Time
	failNext error
}

func newFakeService(now time.Time) *fakeService {
	return &fakeService{records: map[string]agents.SecretRecord{}, now: now}
}

func (f *fakeService) Create(_ context.Context, r agents.CreateRequest) (agents.Result, error) {
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return agents.Result{}, err
	}
	f.creates++
	f.records[r.AgentName] = agents.SecretRecord{AgentName: r.AgentName, DisplayName: r.DisplayName, MASUserID: "mas-" + r.AgentName, SessionID: "s1", AccessToken: "synthetic-token-1", Generation: 1, Status: agents.StatusActive, CreatedAt: f.now, UpdatedAt: f.now}
	return agents.Result{AgentName: r.AgentName}, nil
}

func (f *fakeService) Rotate(_ context.Context, name string) (agents.Result, error) {
	r, ok := f.records[name]
	if !ok {
		return agents.Result{}, agents.ErrNotFound
	}
	f.rotates++
	r.Generation++
	r.AccessToken = fmt.Sprintf("synthetic-token-%d", r.Generation)
	r.Status = agents.StatusActive
	r.UpdatedAt = f.now
	f.records[name] = r
	return agents.Result{AgentName: name, Generation: r.Generation}, nil
}

func (f *fakeService) Deactivate(_ context.Context, name string) (agents.Result, error) {
	r, ok := f.records[name]
	if !ok {
		return agents.Result{}, agents.ErrNotFound
	}
	f.deacts++
	r.Status, r.AccessToken, r.SessionID = agents.StatusDeactivated, "", ""
	f.records[name] = r
	return agents.Result{AgentName: name}, nil
}

func (f *fakeService) GetAgent(_ context.Context, name string) (agents.SecretRecord, error) {
	r, ok := f.records[name]
	if !ok {
		return agents.SecretRecord{}, agents.ErrNotFound
	}
	return r, nil
}

func matrixAgent(namespace, name string, spec map[string]any, created time.Time) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": Group + "/" + Version,
		"kind":       "MatrixAgent",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": namespace + "-" + name, "generation": int64(1)},
		"spec":       spec,
	}}
	obj.SetCreationTimestamp(metav1.NewTime(created))
	return obj
}

type harness struct {
	op      *Operator
	svc     *fakeService
	dyn     *dynamicfake.FakeDynamicClient
	kube    *kubefake.Clientset
	clock   time.Time
	podDels int
}

func newHarness(t *testing.T, objs ...runtime.Object) *harness {
	t.Helper()
	clock := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{GVR: "MatrixAgentList"}, objs...)
	replicas := int32(1)
	kube := kubefake.NewSimpleClientset(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "hermes-lead", Namespace: ns},
		Spec:       appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "hermes"}}},
	})
	h := &harness{svc: newFakeService(clock), dyn: dyn, kube: kube, clock: clock}
	kube.PrependReactor("delete-collection", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		h.podDels++
		return true, nil, nil
	})
	op, err := New(dyn, kube, h.svc, h.svc, Config{
		Namespaces:           []string{ns, "tenant-b"},
		RotateAfter:          24 * time.Hour,
		HomeserverURL:        "https://matrix.example.invalid",
		MatrixUserIDTemplate: "@{localpart}:example.invalid",
		DeviceIDTemplate:     "agent-{agent_name}",
	})
	if err != nil {
		t.Fatal(err)
	}
	op.now = func() time.Time { return h.clock }
	h.op = op
	return h
}

func (h *harness) get(t *testing.T, namespace, name string) *unstructured.Unstructured {
	t.Helper()
	obj, err := h.dyn.Resource(GVR).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

func (h *harness) secret(t *testing.T, name string) *corev1.Secret {
	t.Helper()
	s, err := h.kube.CoreV1().Secrets(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func phase(obj *unstructured.Unstructured) string {
	p, _, _ := unstructured.NestedString(obj.Object, "status", "phase")
	return p
}

func baseSpec() map[string]any {
	return map[string]any{"agentName": "lead", "displayName": "Lead", "secretName": "lead-matrix", "restartDeployments": []any{"hermes-lead"}}
}

func TestCreatesAgentWritesSecretAndIsIdempotent(t *testing.T) {
	h := newHarness(t, matrixAgent(ns, "lead", baseSpec(), time.Now()))
	ctx := context.Background()
	if err := h.op.ReconcileAll(ctx); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	obj := h.get(t, ns, "lead")
	if phase(obj) != PhaseReady || h.svc.creates != 1 {
		t.Fatalf("phase=%q creates=%d", phase(obj), h.svc.creates)
	}
	if !containsString(obj.GetFinalizers(), Finalizer) {
		t.Fatal("finalizer missing")
	}
	s := h.secret(t, "lead-matrix")
	if string(s.Data["access-token"]) != "synthetic-token-1" || string(s.Data["user-id"]) != "@lead:example.invalid" || string(s.Data["device-id"]) != "agent-lead" || string(s.Data["homeserver"]) != "https://matrix.example.invalid" {
		t.Fatalf("secret data = %v", s.Data)
	}
	if len(s.OwnerReferences) != 1 || s.OwnerReferences[0].Kind != "MatrixAgent" {
		t.Fatalf("owner refs = %v", s.OwnerReferences)
	}
	if h.podDels != 1 {
		t.Fatalf("pod restarts after create = %d", h.podDels)
	}
	for i := 0; i < 3; i++ {
		if err := h.op.ReconcileAll(ctx); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	if h.svc.creates != 1 || h.svc.rotates != 0 || h.podDels != 1 {
		t.Fatalf("not idempotent: creates=%d rotates=%d restarts=%d", h.svc.creates, h.svc.rotates, h.podDels)
	}
}

func TestRotatesOnRequestAndOnAge(t *testing.T) {
	h := newHarness(t, matrixAgent(ns, "lead", baseSpec(), time.Now()))
	ctx := context.Background()
	if err := h.op.ReconcileAll(ctx); err != nil {
		t.Fatal(err)
	}
	obj := h.get(t, ns, "lead")
	_ = unstructured.SetNestedField(obj.Object, "2026-10-08", "spec", "rotationToken")
	if _, err := h.dyn.Resource(GVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := h.op.ReconcileAll(ctx); err != nil {
		t.Fatal(err)
	}
	if h.svc.rotates != 1 || string(h.secret(t, "lead-matrix").Data["access-token"]) != "synthetic-token-2" || h.podDels != 2 {
		t.Fatalf("requested rotation: rotates=%d restarts=%d", h.svc.rotates, h.podDels)
	}
	if err := h.op.ReconcileAll(ctx); err != nil || h.svc.rotates != 1 {
		t.Fatalf("rotation token must be consumed once: rotates=%d err=%v", h.svc.rotates, err)
	}
	h.clock = h.clock.Add(25 * time.Hour)
	if err := h.op.ReconcileAll(ctx); err != nil {
		t.Fatal(err)
	}
	if h.svc.rotates != 2 || string(h.secret(t, "lead-matrix").Data["access-token"]) != "synthetic-token-3" {
		t.Fatalf("age rotation: rotates=%d", h.svc.rotates)
	}
	got, _, _ := unstructured.NestedInt64(h.get(t, ns, "lead").Object, "status", "tokenGeneration")
	if got != 3 {
		t.Fatalf("status.tokenGeneration = %d", got)
	}
}

func TestExistingAccountRequiresAdoption(t *testing.T) {
	h := newHarness(t, matrixAgent(ns, "lead", baseSpec(), time.Now()))
	h.svc.records["lead"] = agents.SecretRecord{AgentName: "lead", MASUserID: "mas-lead", AccessToken: "synthetic-existing", Generation: 4, Status: agents.StatusActive, UpdatedAt: h.clock}
	ctx := context.Background()
	if err := h.op.ReconcileAll(ctx); err == nil || phase(h.get(t, ns, "lead")) != PhaseConflict {
		t.Fatalf("expected conflict, got err=%v phase=%q", err, phase(h.get(t, ns, "lead")))
	}
	if _, err := h.kube.CoreV1().Secrets(ns).Get(ctx, "lead-matrix", metav1.GetOptions{}); err == nil {
		t.Fatal("secret must not be written without adoption")
	}
	obj := h.get(t, ns, "lead")
	_ = unstructured.SetNestedField(obj.Object, true, "spec", "adoptExisting")
	if _, err := h.dyn.Resource(GVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := h.op.ReconcileAll(ctx); err != nil {
		t.Fatal(err)
	}
	if h.svc.creates != 0 || h.svc.rotates != 0 || string(h.secret(t, "lead-matrix").Data["access-token"]) != "synthetic-existing" {
		t.Fatalf("adoption must keep the current token: creates=%d rotates=%d", h.svc.creates, h.svc.rotates)
	}
}

func TestAdoptsUnownedSecretOnlyWhenAllowed(t *testing.T) {
	h := newHarness(t, matrixAgent(ns, "lead", baseSpec(), time.Now()))
	ctx := context.Background()
	_, _ = h.kube.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "lead-matrix", Namespace: ns}, Data: map[string][]byte{"access-token": []byte("synthetic-old")}}, metav1.CreateOptions{})
	if err := h.op.ReconcileAll(ctx); err == nil || !strings.Contains(phaseMessage(h.get(t, ns, "lead")), "not owned") {
		t.Fatalf("expected ownership failure, err=%v", err)
	}
	if string(h.secret(t, "lead-matrix").Data["access-token"]) != "synthetic-old" {
		t.Fatal("foreign secret was overwritten")
	}
}

func phaseMessage(obj *unstructured.Unstructured) string {
	m, _, _ := unstructured.NestedString(obj.Object, "status", "message")
	return m
}

func TestSecondClaimOnSameAgentConflicts(t *testing.T) {
	older := matrixAgent(ns, "lead", baseSpec(), time.Now().Add(-time.Hour))
	newer := matrixAgent("tenant-b", "lead", baseSpec(), time.Now())
	h := newHarness(t, older, newer)
	err := h.op.ReconcileAll(context.Background())
	if err == nil || phase(h.get(t, "tenant-b", "lead")) != PhaseConflict || phase(h.get(t, ns, "lead")) != PhaseReady {
		t.Fatalf("err=%v a=%q b=%q", err, phase(h.get(t, ns, "lead")), phase(h.get(t, "tenant-b", "lead")))
	}
	if _, err := h.kube.CoreV1().Secrets("tenant-b").Get(context.Background(), "lead-matrix", metav1.GetOptions{}); err == nil {
		t.Fatal("conflicting claim received a token")
	}
}

func TestDeletionPolicies(t *testing.T) {
	for _, policy := range []string{"Retain", "Deactivate"} {
		spec := baseSpec()
		spec["deletionPolicy"] = policy
		h := newHarness(t, matrixAgent(ns, "lead", spec, time.Now()))
		ctx := context.Background()
		if err := h.op.ReconcileAll(ctx); err != nil {
			t.Fatal(err)
		}
		obj := h.get(t, ns, "lead")
		now := metav1.Now()
		obj.SetDeletionTimestamp(&now)
		if _, err := h.dyn.Resource(GVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := h.op.ReconcileAll(ctx); err != nil {
			t.Fatal(err)
		}
		wantDeacts := map[string]int{"Retain": 0, "Deactivate": 1}[policy]
		if h.svc.deacts != wantDeacts {
			t.Fatalf("%s: deactivations=%d", policy, h.svc.deacts)
		}
		if containsString(h.get(t, ns, "lead").GetFinalizers(), Finalizer) {
			t.Fatalf("%s: finalizer not removed", policy)
		}
	}
}

func TestFailureIsReportedAndRetried(t *testing.T) {
	h := newHarness(t, matrixAgent(ns, "lead", baseSpec(), time.Now()))
	h.svc.failNext = fmt.Errorf("synthetic MAS outage")
	ctx := context.Background()
	if err := h.op.ReconcileAll(ctx); err == nil || phase(h.get(t, ns, "lead")) != PhaseFailed {
		t.Fatalf("expected failure, err=%v", err)
	}
	if err := h.op.ReconcileAll(ctx); err != nil || phase(h.get(t, ns, "lead")) != PhaseReady {
		t.Fatalf("retry: err=%v phase=%q", err, phase(h.get(t, ns, "lead")))
	}
}
