# PayzCore for XenForo 2

Blockchain transaction monitoring integration for XenForo 2 user upgrades. Accept stablecoin payments (USDT/USDC) on multiple networks (TRC20, BEP20, ERC20, Polygon, Arbitrum) for premium memberships.

PayzCore is a **non-custodial** monitoring API -- it watches blockchain addresses for incoming transfers and notifies your XenForo installation via webhooks. It does not hold, transmit, or custody any funds.

## Important

**PayzCore is a blockchain monitoring service, not a payment processor.** All payments are sent directly to your own wallet addresses. PayzCore never holds, transfers, or has access to your funds.

- **Your wallets, your funds** — You provide your own wallet (HD xPub or static addresses). Customers pay directly to your addresses.
- **Read-only monitoring** — PayzCore watches the blockchain for incoming transactions and sends webhook notifications. That's it.
- **Protection Key security** — Sensitive operations like wallet management, address changes, and API key regeneration require a Protection Key that only you set. PayzCore cannot perform these actions without your authorization.
- **Your responsibility** — You are responsible for securing your own wallets and private keys. PayzCore provides monitoring and notification only.

## Requirements

- XenForo 2.2.0 or higher
- PHP 7.4 or higher
- A PayzCore account with an active project ([app.payzcore.com](https://app.payzcore.com))

## Installation

### Method 1: Install via Admin Panel

1. Download the latest release archive
2. Log into your XenForo admin panel
3. Navigate to **Add-ons** > **Install/upgrade from archive**
4. Upload the archive and follow the prompts

### Method 2: Manual Installation

Copy the `upload/src/addons/PayzCore/` directory into your XenForo installation:

```
your-xenforo/
└── src/
    └── addons/
        └── PayzCore/
            ├── addon.json
            ├── Setup.php
            ├── Payment/
            │   └── PayzCore.php
            └── _output/
                ├── phrases/
                └── templates/
```

Then go to **Add-ons** in the admin panel and install from the list.

## Configuration

### 1. Create a Payment Profile

1. Go to **Setup** > **Payment profiles**
2. Click **Add payment profile**
3. Select **PayzCore - Stablecoin Monitoring** as the provider
4. Configure the following settings:

| Setting | Description | Example |
|---------|-------------|---------|
| **API URL** | PayzCore API base URL | `https://api.payzcore.com` |
| **API Key** | Your project API key | `pk_live_abc123...` |
| **Webhook Secret** | Webhook signing secret | `whsec_xyz789...` |
| **Payment Expiry** | Minutes before monitoring expires (min 10) | `60` |

Networks and tokens are **auto-configured** from your PayzCore project. When you save the payment profile, the add-on fetches available networks via the API and displays the connection status.

You can find your API Key and Webhook Secret in the PayzCore dashboard under **Projects** > your project > **Settings**.

### 2. Configure Webhook URL in PayzCore

In your PayzCore project settings, set the webhook URL to:

```
https://yourdomain.com/payment_callback.php?_xfProvider=payzCore
```

Replace `yourdomain.com` with your actual forum domain. This URL is also shown in the payment profile configuration form.

### 3. Set Up User Upgrades

1. Go to **Setup** > **User upgrades**
2. Create or edit a user upgrade
3. Set the **Cost** and ensure the **Cost currency** is `USD`
4. Under **Payment profile associations**, check the PayzCore profile
5. Save the user upgrade

## How It Works

### Payment Flow

1. User views the Account Upgrades page and selects a premium membership
2. If multiple networks are enabled, the user selects their preferred network and token
3. The add-on creates a monitoring request via the PayzCore API
4. User sees a payment page with:
   - Deposit address (with copy-to-clipboard)
   - QR code for easy wallet scanning
   - Exact stablecoin amount to send
   - Countdown timer showing time remaining
   - Real-time status polling (every 15 seconds)
5. User sends the stablecoin from their wallet to the displayed address
6. PayzCore detects the incoming transfer on the blockchain
7. PayzCore sends a signed webhook to your XenForo callback URL
8. The add-on verifies the signature and activates the user upgrade

### Webhook Events

| Event | Action |
|-------|--------|
| `payment.completed` | User upgrade activated |
| `payment.overpaid` | User upgrade activated (overpayment logged) |
| `payment.partial` | Logged only -- upgrade remains inactive |
| `payment.expired` | Logged only -- user can retry |
| `payment.cancelled` | Payment cancelled by the merchant |

### Security

- All webhook payloads are verified using **HMAC-SHA256** signature
- Timing-safe comparison prevents timing attacks
- Purchase request validation ensures the payment belongs to a real upgrade
- Transaction ID deduplication prevents double-crediting
- Poll endpoint validates user session ownership (no enumeration)
- API key stays server-side (poll requests proxy through XenForo)

## Supported Networks and Tokens

| Network | Token | Notes |
|-------|-------|-------|
| TRC20 (Tron) | USDT | Most popular |
| BEP20 (BSC) | USDT, USDC | Low fees |
| ERC20 (Ethereum) | USDT, USDC | Higher gas fees |
| Polygon | USDT, USDC | Lowest fees |
| Arbitrum | USDT, USDC | Low fees |

**Note:** USDC is not available on TRC20 (Circle discontinued TRC20 USDC).

## Currency Configuration

PayzCore monitors stablecoin transfers (USDT/USDC). Your XenForo user upgrades **must be priced in USD** for the amounts to match correctly.

In **Setup** > **User upgrades**, set the cost currency to `USD`.

## Troubleshooting

### Check Payment Logs

1. Go to **Logs** > **Payment provider log**
2. Filter by "payzCore" to see all API interactions and webhook deliveries

### Common Issues

**"No payment profile found" in logs**
- Ensure the payment profile is active in Setup > Payment profiles
- Verify the webhook URL uses the correct `_xfProvider=payzCore` parameter

**"Invalid HMAC-SHA256 signature" in logs**
- Verify the Webhook Secret in the payment profile matches your PayzCore project
- Ensure no proxy or WAF is modifying the request body

**"Unable to create monitoring request"**
- Check that your server can reach the PayzCore API URL
- Verify the API key is correct and the project is active
- Check PHP error logs for connection errors

**User upgrade not activating after transfer**
- Check the payment provider log for any error entries
- Verify the webhook URL is set correctly in the PayzCore dashboard
- Ensure the transfer was for the exact amount displayed

**Payment page shows "currency not supported"**
- User upgrades must be priced in USD
- Go to Setup > User upgrades and change the cost currency

### Recurring Upgrades

PayzCore does not support automatic recurring payments. For user upgrades with a duration (e.g., 30 days), the user will need to manually renew by making a new transfer when the upgrade expires.

## File Structure

```
src/addons/PayzCore/
├── addon.json                          # Add-on metadata
├── Setup.php                           # Install/uninstall (registers provider)
├── Payment/
│   └── PayzCore.php                    # Payment provider implementation
│       # - getTitle()                  # Provider display name
│       # - verifyConfig()             # Validate admin settings
│       # - initiatePayment()          # Create monitoring request
│       # - processPayment()           # Handle return visits
│       # - setupCallback()            # Parse webhook / poll requests
│       # - validateCallback()         # HMAC-SHA256 verification
│       # - validateTransaction()      # Duplicate detection
│       # - getPaymentResult()         # Map events to XF states
│       # - prepareLogData()           # Structured log entries
└── _output/
    ├── phrases/                        # Language strings (48 phrases)
    └── templates/
        ├── admin/
        │   └── payment_profile_payzCore.html   # Admin config form
        └── public/
            └── payzcore_payment.html            # Payment page (QR, address, countdown)
```

## API Reference

This add-on uses two PayzCore API endpoints:

- **POST /v1/payments** -- Create a monitoring request
- **GET /v1/payments/:id** -- Check payment status
- **GET /v1/config** -- Fetch available networks/tokens (on config save)

Full API documentation: [docs.payzcore.com](https://docs.payzcore.com)

## Before Going Live

**Always test your setup before accepting real payments:**

1. **Verify your wallet** — In the PayzCore dashboard, verify that your wallet addresses are correct. For HD wallets, click "Verify Key" and compare address #0 with your wallet app.
2. **Run a test order** — Place a test order for a small amount ($1–5) and complete the payment. Verify the funds arrive in your wallet.
3. **Test sweeping** — Send the test funds back out to confirm you control the addresses with your private keys.

> **Warning:** Wrong wallet configuration means payments go to addresses you don't control. Funds sent to incorrect addresses are permanently lost. PayzCore is watch-only and cannot recover funds. Please test before going live.

## Localization

All user-facing text is managed through XenForo's phrase system (48 phrases). To translate the payment page and admin settings to another language:

1. Go to **Appearance** > **Phrases**
2. Search for `payzcore_`
3. Click any phrase to edit its text
4. Save — changes take effect immediately

For multi-language forums, create a new language under **Appearance** > **Languages**, then translate the phrases for that language. XenForo will automatically show the correct language based on user preference.

### Key Phrases

| Phrase | Default | Used On |
|--------|---------|---------|
| `payzcore_payment_title` | Pay with Stablecoin | Page title |
| `payzcore_select_network` | Select Network | Checkout selector |
| `payzcore_send_exact_amount` | Send exactly this amount... | Payment page |
| `payzcore_waiting_for_transfer` | Waiting for transfer... | Status text |
| `payzcore_network_warning` | Only send {token} on the {network}... | Warning message |

All 48 phrases follow the `payzcore_` prefix convention.

## License

MIT

## See Also

- [Getting Started](https://docs.payzcore.com/getting-started) — Account setup and first payment
- [Webhooks Guide](https://docs.payzcore.com/guides/webhooks) — Events, headers, and signature verification
- [Supported Networks](https://docs.payzcore.com/guides/networks) — Available networks and tokens
- [Error Reference](https://docs.payzcore.com/guides/errors) — HTTP status codes and troubleshooting
- [API Reference](https://docs.payzcore.com) — Interactive API documentation

## Support

- Documentation: [docs.payzcore.com](https://docs.payzcore.com)
- Website: [payzcore.com](https://payzcore.com)
- Email: support@payzcore.com
