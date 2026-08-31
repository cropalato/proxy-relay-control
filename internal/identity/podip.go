package identity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

// PodIPIndex is the informer index name mapping pod IPs to pods.
const PodIPIndex = "relayPodIP"

// DefaultNegativeTTL bounds how long an unresolvable address is remembered.
// It is deliberately short: a pod that has only just been scheduled will miss
// the cache, and callers should not be denied for seconds because of it.
const DefaultNegativeTTL = 2 * time.Second

// PodIPProvider resolves clients by matching the connection source IP against
// pod IPs known to the API server.
type PodIPProvider struct {
	client    kubernetes.Interface
	podIndex  cache.Indexer
	podSynced cache.InformerSynced
	nsLister  corelisters.NamespaceLister
	nsSynced  cache.InformerSynced

	negTTL time.Duration

	mu       sync.Mutex
	negative map[string]time.Time
}

// NewPodIPProvider wires a provider onto the given informer factory. The caller
// is responsible for starting the factory and waiting for its caches to sync;
// use WaitForCacheSync below before serving traffic, since an unsynced cache
// would deny legitimate clients.
func NewPodIPProvider(factory informers.SharedInformerFactory, client kubernetes.Interface, negTTL time.Duration) (*PodIPProvider, error) {
	if negTTL <= 0 {
		negTTL = DefaultNegativeTTL
	}

	podInformer := factory.Core().V1().Pods()
	if err := podInformer.Informer().AddIndexers(cache.Indexers{PodIPIndex: podIPIndexFunc}); err != nil {
		return nil, fmt.Errorf("identity: add pod IP index: %w", err)
	}
	nsInformer := factory.Core().V1().Namespaces()

	return &PodIPProvider{
		client:    client,
		podIndex:  podInformer.Informer().GetIndexer(),
		podSynced: podInformer.Informer().HasSynced,
		nsLister:  nsInformer.Lister(),
		nsSynced:  nsInformer.Informer().HasSynced,
		negTTL:    negTTL,
		negative:  make(map[string]time.Time),
	}, nil
}

// WaitForCacheSync blocks until both informers have populated.
func (p *PodIPProvider) WaitForCacheSync(ctx context.Context) bool {
	return cache.WaitForCacheSync(ctx.Done(), p.podSynced, p.nsSynced)
}

// HasSynced reports whether the provider is ready to serve.
func (p *PodIPProvider) HasSynced() bool { return p.podSynced() && p.nsSynced() }

func podIPIndexFunc(obj any) ([]string, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(pod.Status.PodIPs)+1)
	var ips []string
	add := func(ip string) {
		if ip == "" {
			return
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return
		}
		key := addr.Unmap().String()
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		ips = append(ips, key)
	}
	add(pod.Status.PodIP)
	for _, ip := range pod.Status.PodIPs {
		add(ip.IP)
	}
	return ips, nil
}

// Identify resolves the client address to a workload.
func (p *PodIPProvider) Identify(ctx context.Context, remote net.Addr) (*Identity, error) {
	addr, err := AddrToIP(remote)
	if err != nil {
		return nil, err
	}
	key := addr.String()

	if p.negativeHit(key) {
		return nil, fmt.Errorf("%w: %s", ErrUnknownClient, key)
	}

	pod, err := p.lookup(ctx, key)
	if err != nil {
		if errors.Is(err, ErrUnknownClient) {
			p.rememberMiss(key)
		}
		return nil, err
	}

	// A host-network pod's address is its node's address, shared with the kubelet
	// and every other host-network pod on that node. Attributing egress to one of
	// them would be arbitrary, so refuse rather than guess.
	if pod.Spec.HostNetwork {
		return nil, fmt.Errorf("%w: %s/%s at %s", ErrHostNetwork, pod.Namespace, pod.Name, key)
	}

	id := &Identity{
		Namespace:      pod.Namespace,
		Pod:            pod.Name,
		ServiceAccount: pod.Spec.ServiceAccountName,
		PodLabels:      pod.Labels,
		SourceIP:       addr,
	}
	if ns, err := p.nsLister.Get(pod.Namespace); err == nil {
		id.NamespaceLabels = ns.Labels
	} else if ns, err := p.client.CoreV1().Namespaces().Get(ctx, pod.Namespace, metav1.GetOptions{}); err == nil {
		id.NamespaceLabels = ns.Labels
	} else {
		// Namespace labels drive policy selection, so failing to read them must not
		// silently degrade into "no labels" and a wrong allow/deny.
		return nil, fmt.Errorf("identity: read namespace %q for pod %s/%s: %w", pod.Namespace, pod.Namespace, pod.Name, err)
	}
	return id, nil
}

// lookup consults the informer index first, then falls back to a live read. The
// fallback covers the window between a pod becoming ready and the watch event
// arriving, which is exactly when a fast-starting workload makes its first call.
func (p *PodIPProvider) lookup(ctx context.Context, ip string) (*corev1.Pod, error) {
	objs, err := p.podIndex.ByIndex(PodIPIndex, ip)
	if err != nil {
		return nil, fmt.Errorf("identity: index lookup for %s: %w", ip, err)
	}
	pods := make([]*corev1.Pod, 0, len(objs))
	for _, obj := range objs {
		if pod, ok := obj.(*corev1.Pod); ok {
			pods = append(pods, pod)
		}
	}
	if pod, err := pickPod(pods, ip); err == nil {
		return pod, nil
	} else if !errors.Is(err, ErrUnknownClient) {
		return nil, err
	}

	list, err := p.client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
		FieldSelector: "status.podIP=" + ip,
		Limit:         8,
	})
	if err != nil {
		return nil, fmt.Errorf("identity: live lookup for %s: %w", ip, err)
	}
	live := make([]*corev1.Pod, 0, len(list.Items))
	for i := range list.Items {
		live = append(live, &list.Items[i])
	}
	return pickPod(live, ip)
}

// pickPod resolves the pod-IP reuse race. When a terminating pod and its
// replacement briefly share an address, the live pod is the one making the
// request; only genuine ambiguity between two live pods is an error.
func pickPod(pods []*corev1.Pod, ip string) (*corev1.Pod, error) {
	switch len(pods) {
	case 0:
		return nil, fmt.Errorf("%w: %s", ErrUnknownClient, ip)
	case 1:
		return pods[0], nil
	}

	var live []*corev1.Pod
	for _, pod := range pods {
		if pod.DeletionTimestamp != nil {
			continue
		}
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		live = append(live, pod)
	}
	if len(live) == 1 {
		return live[0], nil
	}
	if len(live) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrUnknownClient, ip)
	}
	return nil, fmt.Errorf("%w: %s matches %s/%s and %s/%s", ErrAmbiguousClient, ip,
		live[0].Namespace, live[0].Name, live[1].Namespace, live[1].Name)
}

func (p *PodIPProvider) negativeHit(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	until, ok := p.negative[ip]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(p.negative, ip)
		return false
	}
	return true
}

func (p *PodIPProvider) rememberMiss(ip string) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	// Sweep opportunistically; the map only ever holds addresses seen recently.
	if len(p.negative) > 1024 {
		for k, until := range p.negative {
			if now.After(until) {
				delete(p.negative, k)
			}
		}
	}
	p.negative[ip] = now.Add(p.negTTL)
}

var _ Provider = (*PodIPProvider)(nil)
