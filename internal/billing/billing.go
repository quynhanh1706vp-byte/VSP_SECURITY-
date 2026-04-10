package billing

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stripe/stripe-go/v76"
	"github.com/stripe/stripe-go/v76/checkout/session"
	"github.com/stripe/stripe-go/v76/customer"
	"github.com/stripe/stripe-go/v76/webhook"
	"github.com/vsp/platform/internal/auth"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PriceIDs map plan name → Stripe Price ID
var PriceIDs = map[string]string{
	"starter":      os.Getenv("STRIPE_PRICE_STARTER"),
	"professional": os.Getenv("STRIPE_PRICE_PROFESSIONAL"),
	"enterprise":   os.Getenv("STRIPE_PRICE_ENTERPRISE"),
}

type Handler struct {
	DB *pgxpool.Pool
}

// POST /api/v1/billing/checkout — tạo Stripe Checkout session
func (h *Handler) CreateCheckout(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		Plan      string `json:"plan"`
		Interval  string `json:"interval"` // monthly | yearly
		SuccessURL string `json:"success_url"`
		CancelURL  string `json:"cancel_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if req.Plan == "" {
		req.Plan = "starter"
	}
	if req.Interval == "" {
		req.Interval = "monthly"
	}
	if req.SuccessURL == "" {
		req.SuccessURL = os.Getenv("DASHBOARD_URL") + "/billing?success=1"
	}
	if req.CancelURL == "" {
		req.CancelURL = os.Getenv("DASHBOARD_URL") + "/billing?cancel=1"
	}

	priceID := PriceIDs[req.Plan]
	if priceID == "" {
		http.Error(w, `{"error":"invalid plan"}`, http.StatusBadRequest)
		return
	}

	stripe.Key = os.Getenv("STRIPE_SECRET_KEY")

	// Lấy hoặc tạo Stripe customer
	var customerID, tenantName string
	h.DB.QueryRow(r.Context(),
		`SELECT COALESCE(stripe_customer_id,''), name FROM tenants WHERE id=$1`,
		claims.TenantID,
	).Scan(&customerID, &tenantName) //nolint

	if customerID == "" {
		c, err := customer.New(&stripe.CustomerParams{
			Email: stripe.String(claims.Email),
			Name:  stripe.String(tenantName),
			Metadata: map[string]string{
				"tenant_id": claims.TenantID,
			},
		})
		if err != nil {
			log.Error().Err(err).Msg("stripe: create customer failed")
			http.Error(w, `{"error":"failed to create customer"}`, http.StatusInternalServerError)
			return
		}
		customerID = c.ID
		h.DB.Exec(r.Context(),
			`UPDATE tenants SET stripe_customer_id=$1 WHERE id=$2`,
			customerID, claims.TenantID,
		) //nolint
	}

	// Tạo checkout session
	params := &stripe.CheckoutSessionParams{
		Customer: stripe.String(customerID),
		Mode:     stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(priceID),
				Quantity: stripe.Int64(1),
			},
		},
		SuccessURL: stripe.String(req.SuccessURL),
		CancelURL:  stripe.String(req.CancelURL),
		SubscriptionData: &stripe.CheckoutSessionSubscriptionDataParams{
			Metadata: map[string]string{
				"tenant_id": claims.TenantID,
				"plan":      req.Plan,
			},
		},
	}

	s, err := session.New(params)
	if err != nil {
		log.Error().Err(err).Msg("stripe: checkout session failed")
		http.Error(w, `{"error":"failed to create checkout"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": s.URL})
}

// GET /api/v1/billing/status — billing status của tenant hiện tại
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var status struct {
		Plan               string     `json:"plan"`
		SubscriptionStatus string     `json:"subscription_status"`
		CurrentPeriodEnd   *time.Time `json:"current_period_end"`
		CancelAtPeriodEnd  bool       `json:"cancel_at_period_end"`
		StripeCustomerID   string     `json:"stripe_customer_id,omitempty"`
	}

	h.DB.QueryRow(r.Context(),
		`SELECT plan, subscription_status, current_period_end, cancel_at_period_end,
		        COALESCE(stripe_customer_id,'')
		 FROM tenants WHERE id=$1`,
		claims.TenantID,
	).Scan(
		&status.Plan,
		&status.SubscriptionStatus,
		&status.CurrentPeriodEnd,
		&status.CancelAtPeriodEnd,
		&status.StripeCustomerID,
	)
	// Default values if DB scan fails (tenant not yet in billing)
	if status.Plan == "" { status.Plan = "starter" }
	if status.SubscriptionStatus == "" { status.SubscriptionStatus = "active" }

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// POST /api/v1/billing/webhook — Stripe webhook events
func (h *Handler) Webhook(w http.ResponseWriter, r *http.Request) {
	const maxBytes = 65536
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	webhookSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	if webhookSecret == "" {
		log.Error().Msg("stripe webhook: STRIPE_WEBHOOK_SECRET not set — rejecting all webhooks")
		http.Error(w, "webhook not configured", http.StatusServiceUnavailable)
		return
	}
	event, err := webhook.ConstructEventWithOptions(body,
		r.Header.Get("Stripe-Signature"), webhookSecret,
		webhook.ConstructEventOptions{IgnoreAPIVersionMismatch: true})
	if err != nil {
		log.Warn().Err(err).Msg("stripe webhook: invalid signature")
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}

	switch event.Type {
	case "customer.subscription.created", "customer.subscription.updated":
		var sub stripe.Subscription
		if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
			break
		}
		tenantID := sub.Metadata["tenant_id"]
		if tenantID == "" {
			log.Warn().Str("sub_id", sub.ID).Msg("stripe webhook: missing tenant_id in metadata")
			break
		}
		plan := sub.Metadata["plan"]
		if plan == "" { plan = "starter" }
		periodEnd := time.Unix(sub.CurrentPeriodEnd, 0)
		h.DB.Exec(r.Context(),
			`UPDATE tenants SET
				stripe_subscription_id=$1,
				subscription_status=$2,
				plan=$3,
				current_period_end=$4,
				cancel_at_period_end=$5
			 WHERE id=$6`,
			sub.ID, string(sub.Status), plan, periodEnd, sub.CancelAtPeriodEnd, tenantID,
		) //nolint
		log.Info().Str("tenant", tenantID).Str("status", string(sub.Status)).Msg("stripe: subscription updated")

	case "customer.subscription.deleted":
		var sub stripe.Subscription
		if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
			break
		}
		tenantID := sub.Metadata["tenant_id"]
		if tenantID == "" {
			log.Warn().Str("sub_id", sub.ID).Msg("stripe webhook: missing tenant_id on delete")
			break
		}
		h.DB.Exec(r.Context(),
			`UPDATE tenants SET subscription_status='canceled', plan='starter' WHERE id=$1`,
			tenantID,
		) //nolint
		log.Info().Str("tenant", tenantID).Msg("stripe: subscription canceled")

	case "invoice.payment_failed":
		var inv stripe.Invoice
		if err := json.Unmarshal(event.Data.Raw, &inv); err != nil {
			break
		}
		if inv.Subscription != nil {
			h.DB.Exec(r.Context(),
				`UPDATE tenants SET subscription_status='past_due'
				 WHERE stripe_subscription_id=$1`,
				inv.Subscription.ID,
			) //nolint
		}
		log.Warn().Msg("stripe: invoice payment failed")
	}

	w.WriteHeader(http.StatusOK)
}
