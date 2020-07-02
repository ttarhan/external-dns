/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
	"sigs.k8s.io/external-dns/registry"
	"sigs.k8s.io/external-dns/source"
)

var (
	registryErrorsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "external_dns",
			Subsystem: "registry",
			Name:      "errors_total",
			Help:      "Number of Registry errors.",
		},
	)
	sourceErrorsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "external_dns",
			Subsystem: "source",
			Name:      "errors_total",
			Help:      "Number of Source errors.",
		},
	)
	sourceEndpointsTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "external_dns",
			Subsystem: "source",
			Name:      "endpoints_total",
			Help:      "Number of Endpoints in all sources",
		},
	)
	registryEndpointsTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "external_dns",
			Subsystem: "registry",
			Name:      "endpoints_total",
			Help:      "Number of Endpoints in the registry",
		},
	)
	lastSyncTimestamp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "external_dns",
			Subsystem: "controller",
			Name:      "last_sync_timestamp_seconds",
			Help:      "Timestamp of last successful sync with the DNS provider",
		},
	)
	deprecatedRegistryErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Subsystem: "registry",
			Name:      "errors_total",
			Help:      "Number of Registry errors.",
		},
	)
	deprecatedSourceErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Subsystem: "source",
			Name:      "errors_total",
			Help:      "Number of Source errors.",
		},
	)
)

func init() {
	prometheus.MustRegister(registryErrorsTotal)
	prometheus.MustRegister(sourceErrorsTotal)
	prometheus.MustRegister(sourceEndpointsTotal)
	prometheus.MustRegister(registryEndpointsTotal)
	prometheus.MustRegister(lastSyncTimestamp)
	prometheus.MustRegister(deprecatedRegistryErrors)
	prometheus.MustRegister(deprecatedSourceErrors)
}

// Controller is responsible for orchestrating the different components.
// It works in the following way:
// * Ask the DNS provider for current list of endpoints.
// * Ask the Source for the desired list of endpoints.
// * Take both lists and calculate a Plan to move current towards desired state.
// * Tell the DNS provider to apply the changes calucated by the Plan.
type Controller struct {
	Source   source.Source
	Registry registry.Registry
	// The policy that defines which changes to DNS records are allowed
	Policy plan.Policy
	// The interval between individual synchronizations
	Interval time.Duration
	// The DomainFilter defines which DNS records to keep or exclude
	DomainFilter endpoint.DomainFilter
	// The nextRunAt used for throttling and batching reconciliation
	nextRunAt time.Time
	// The nextRunAtMux is for atomic updating of nextRunAt
	nextRunAtMux sync.Mutex
	// Flag to enable synthesizing set identifiers when using provider that does not persist them
	SynthesizeSetIdentifiers bool
}

// RunOnce runs a single iteration of a reconciliation loop.
func (c *Controller) RunOnce(ctx context.Context) error {
	records, err := c.Registry.Records(ctx)
	if err != nil {
		registryErrorsTotal.Inc()
		deprecatedRegistryErrors.Inc()
		return err
	}
	registryEndpointsTotal.Set(float64(len(records)))

	ctx = context.WithValue(ctx, provider.RecordsContextKey, records)

	endpoints, err := c.Source.Endpoints()
	if err != nil {
		sourceErrorsTotal.Inc()
		deprecatedSourceErrors.Inc()
		return err
	}
	sourceEndpointsTotal.Set(float64(len(endpoints)))

	if c.SynthesizeSetIdentifiers {
		c.synthesizeSetIdentifiers(endpoints, records)
	}

	plan := &plan.Plan{
		Policies:           []plan.Policy{c.Policy},
		Current:            records,
		Desired:            endpoints,
		DomainFilter:       c.DomainFilter,
		PropertyComparator: c.Registry.PropertyValuesEqual,
	}

	plan = plan.Calculate()

	err = c.Registry.ApplyChanges(ctx, plan.Changes)
	if err != nil {
		registryErrorsTotal.Inc()
		deprecatedRegistryErrors.Inc()
		return err
	}

	lastSyncTimestamp.SetToCurrentTime()
	return nil
}

// Hack to allow multiple records for same FQDN but different rdata when using providers that don't support
// record-scoped metadata.  set-identifier allows this, but depends on persisting the value with the DNS record.
// Instead, scan the endpoints, build a map of record-details to non-empty set-identifier.  Then scan the records, and
// assign the set-identifiers ephemerally.  This allows plan.Calculate() to successfully determine match the records
// with their endpoints.
func (c *Controller) synthesizeSetIdentifiers(endpoints []*endpoint.Endpoint, records []*endpoint.Endpoint) {
	log.Debugf("scanning for set identifiers in endpoints")
	setIdentifiers := make(map[string]string)
	for _, ep := range endpoints {
		if len(ep.SetIdentifier) > 0 && len(ep.Targets) == 1 {
			key := fmt.Sprintf("%s/%s/%s", ep.RecordType, ep.DNSName, ep.Targets[0])
			setIdentifiers[key] = ep.SetIdentifier
		}
	}
	if len(setIdentifiers) > 0 {
		log.Debugf("found %d set identifiers, scanning records for matches...", len(setIdentifiers))
		for _, record := range records {
			key := fmt.Sprintf("%s/%s/%s", record.RecordType, record.DNSName, record.Targets[0])
			// only assign setIdentifier if record.SetIdentifier is emptpy; we don't want to overwrite any values if
			// this is accidentally enabled with a provider that *does* persist setIdentifier
			if setIdentifier, ok := setIdentifiers[key]; ok && len(record.SetIdentifier) == 0 {
				record.SetIdentifier = setIdentifier
				log.Debugf("assigned set-identifier %s to record %s", setIdentifier, key)
			}
		}
	}
}

// MinInterval is used as window for batching events
const MinInterval = 5 * time.Second

// RunOnceThrottled makes sure execution happens at most once per interval.
func (c *Controller) ScheduleRunOnce(now time.Time) {
	c.nextRunAtMux.Lock()
	defer c.nextRunAtMux.Unlock()
	c.nextRunAt = now.Add(MinInterval)
}

func (c *Controller) ShouldRunOnce(now time.Time) bool {
	c.nextRunAtMux.Lock()
	defer c.nextRunAtMux.Unlock()
	if now.Before(c.nextRunAt) {
		return false
	}
	c.nextRunAt = now.Add(c.Interval)
	return true
}

// Run runs RunOnce in a loop with a delay until context is canceled
func (c *Controller) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if c.ShouldRunOnce(time.Now()) {
			if err := c.RunOnce(ctx); err != nil {
				log.Error(err)
			}
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			log.Info("Terminating main controller loop")
			return
		}
	}
}
