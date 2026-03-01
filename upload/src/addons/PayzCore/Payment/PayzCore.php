<?php
/**
 * PayzCore Payment Provider for XenForo 2
 *
 * Integrates PayzCore blockchain transaction monitoring with XenForo's
 * payment profile system for user upgrades (premium memberships).
 *
 * PayzCore is a non-custodial monitoring API. It watches blockchain
 * addresses for incoming stablecoin transfers (USDT/USDC) and sends
 * webhook notifications when transfers are detected. It does not hold,
 * transmit, or custody any funds.
 *
 * Supported networks: TRC20, BEP20, ERC20, POLYGON, ARBITRUM
 * Supported tokens: USDT, USDC (USDC not available on TRC20)
 *
 * @package    PayzCore
 * @author     PayzCore <support@payzcore.com>
 * @copyright  2026 PayzCore
 * @license    MIT
 * @link       https://payzcore.com
 * @version    1.0.0
 */

namespace PayzCore\Payment;

use XF\Entity\PaymentProfile;
use XF\Entity\PurchaseRequest;
use XF\Mvc\Controller;
use XF\Payment\AbstractProvider;
use XF\Payment\CallbackState;
use XF\Purchasable\Purchase;

class PayzCore extends AbstractProvider
{
    /**
     * User-agent string for API requests.
     */
    const USER_AGENT = 'PayzCore-XenForo/1.0.0';

    /**
     * HTTP request timeout in seconds.
     */
    const TIMEOUT = 30;

    /**
     * Connect timeout in seconds.
     */
    const CONNECT_TIMEOUT = 10;

    /**
     * Network labels for display purposes.
     *
     * @var array
     */
    protected $networkLabels = [
        'TRC20'    => 'Tron (TRC20)',
        'BEP20'    => 'BSC (BEP20)',
        'ERC20'    => 'Ethereum (ERC20)',
        'POLYGON'  => 'Polygon',
        'ARBITRUM' => 'Arbitrum',
    ];

    /**
     * Network short descriptions for the selector UI.
     *
     * @var array
     */
    protected $networkDescriptions = [
        'TRC20'    => 'Most popular',
        'BEP20'    => 'Low fees',
        'ERC20'    => 'Ethereum mainnet',
        'POLYGON'  => 'Lowest fees',
        'ARBITRUM' => 'L2 - Low fees',
    ];

    /**
     * Blockchain explorer base URLs for transaction links.
     *
     * @var array
     */
    protected $explorerUrls = [
        'TRC20'    => 'https://tronscan.org/#/transaction/',
        'BEP20'    => 'https://bscscan.com/tx/',
        'ERC20'    => 'https://etherscan.io/tx/',
        'POLYGON'  => 'https://polygonscan.com/tx/',
        'ARBITRUM' => 'https://arbiscan.io/tx/',
    ];

    /**
     * All valid networks.
     *
     * @var array
     */
    protected $validNetworks = ['TRC20', 'BEP20', 'ERC20', 'POLYGON', 'ARBITRUM'];

    /**
     * All valid tokens.
     *
     * @var array
     */
    protected $validTokens = ['USDT', 'USDC'];

    // -------------------------------------------------------------------------
    // Provider Identity
    // -------------------------------------------------------------------------

    /**
     * @return string
     */
    public function getTitle()
    {
        return 'PayzCore - Stablecoin Monitoring';
    }

    // -------------------------------------------------------------------------
    // Configuration
    // -------------------------------------------------------------------------

    /**
     * Verify configuration options submitted from the admin payment profile form.
     *
     * @param array $options
     * @param array $errors
     * @return bool
     */
    public function verifyConfig(array &$options, &$errors = [])
    {
        // Trim and normalize API URL
        $options['api_url'] = rtrim(trim($options['api_url'] ?? ''), '/');
        if (empty($options['api_url'])) {
            $options['api_url'] = 'https://api.payzcore.com';
        }

        // Validate required fields
        if (empty($options['api_key'])) {
            $errors[] = \XF::phrase('payzcore_api_key_required');
        }

        if (empty($options['webhook_secret'])) {
            $errors[] = \XF::phrase('payzcore_webhook_secret_required');
        }

        // Validate expiry minutes
        $options['expiry_minutes'] = max(10, min(1440, intval($options['expiry_minutes'] ?? 60)));

        // Fetch config from PayzCore API to get available networks/tokens
        if (empty($errors) && !empty($options['api_key'])) {
            $configResult = $this->fetchAndCacheConfig($options['api_url'], $options['api_key'], $options);
            if ($configResult !== true) {
                \XF::logError('PayzCore config fetch: ' . $configResult);
            }
        }

        // Networks and token come from API cache exclusively
        $enabledNetworks = $options['cached_networks'] ?? ($options['cached_chains'] ?? []);
        $enabledNetworks = array_values(array_intersect((array)$enabledNetworks, $this->validNetworks));
        if (empty($enabledNetworks)) {
            $enabledNetworks = ['TRC20'];
        }
        $options['enabled_networks'] = $enabledNetworks;

        $defaultToken = $options['cached_default_token'] ?? 'USDT';
        if (!in_array($defaultToken, $this->validTokens)) {
            $defaultToken = 'USDT';
        }
        $options['default_token'] = $defaultToken;

        // Keep legacy fields for backward compatibility
        $options['network'] = $enabledNetworks[0];
        $options['token'] = $defaultToken;

        return empty($errors);
    }

    /**
     * Fetch project config from PayzCore API and cache in profile options.
     *
     * @param string $apiUrl  API base URL
     * @param string $apiKey  Project API key
     * @param array  &$options Profile options (modified by reference)
     * @return true|string True on success, error string on failure
     */
    protected function fetchAndCacheConfig($apiUrl, $apiKey, array &$options)
    {
        $response = $this->apiRequest($apiUrl, $apiKey, 'GET', '/v1/config');

        if ($response === null) {
            return 'Could not connect to PayzCore API at ' . $apiUrl;
        }

        if (isset($response['error'])) {
            return 'API error: ' . $response['error'];
        }

        // Extract networks from response
        $networks = [];
        $defaultToken = 'USDT';

        if (isset($response['networks']) && is_array($response['networks'])) {
            foreach ($response['networks'] as $networkInfo) {
                if (isset($networkInfo['network'])) {
                    $networks[] = $networkInfo['network'];
                }
            }
        }

        if (isset($response['default_token'])) {
            $defaultToken = $response['default_token'];
        }

        $options['cached_networks'] = $networks;
        $options['cached_default_token'] = $defaultToken;
        $options['cached_at'] = date('Y-m-d H:i:s');

        return true;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Get enabled networks from profile options (API-driven).
     *
     * Reads from cached_networks (fetched from PayzCore API on config save).
     * Falls back to enabled_networks or legacy single network for old installs.
     *
     * @param array $options
     * @return array
     */
    protected function getEnabledNetworks(array $options)
    {
        // Primary: cached networks from API config
        $cachedNetworks = $options['cached_networks'] ?? ($options['cached_chains'] ?? []);
        if (is_array($cachedNetworks) && !empty($cachedNetworks)) {
            $filtered = array_values(array_intersect($cachedNetworks, $this->validNetworks));
            if (!empty($filtered)) {
                return $filtered;
            }
        }

        // Fallback for old installs that haven't re-saved config yet
        $enabledNetworks = $options['enabled_networks'] ?? ($options['enabled_chains'] ?? []);
        if (is_array($enabledNetworks) && !empty($enabledNetworks)) {
            return array_values(array_intersect($enabledNetworks, $this->validNetworks));
        }

        // Final fallback: legacy single network field
        $network = $options['network'] ?? ($options['chain'] ?? 'TRC20');
        return in_array($network, $this->validNetworks) ? [$network] : ['TRC20'];
    }

    /**
     * Get the default token from profile options (API-driven).
     *
     * @param array $options
     * @return string
     */
    protected function getDefaultToken(array $options)
    {
        // Primary: cached default token from API config
        $cachedToken = $options['cached_default_token'] ?? '';
        if (!empty($cachedToken) && in_array($cachedToken, $this->validTokens)) {
            return $cachedToken;
        }

        // Fallback for old installs
        $token = $options['default_token'] ?? ($options['token'] ?? 'USDT');
        return in_array($token, $this->validTokens) ? $token : 'USDT';
    }

    /**
     * Build network options array for the template selector.
     *
     * @param array $enabledNetworks
     * @return array
     */
    protected function buildNetworkOptions(array $enabledNetworks)
    {
        $options = [];
        foreach ($enabledNetworks as $network) {
            $options[] = [
                'code' => $network,
                'name' => isset($this->networkLabels[$network]) ? $this->networkLabels[$network] : $network,
                'desc' => isset($this->networkDescriptions[$network]) ? $this->networkDescriptions[$network] : '',
            ];
        }
        return $options;
    }

    // -------------------------------------------------------------------------
    // Payment Initiation
    // -------------------------------------------------------------------------

    /**
     * Initiate a payment -- shows network selector or creates a monitoring request
     * via the PayzCore API and shows the payment page with address, QR code,
     * and countdown.
     *
     * Two-step flow when multiple networks are enabled:
     *   Step 1: Show network/token selector (form submits back here)
     *   Step 2: Create PayzCore payment with selected network, show payment UI
     *
     * Called when a user clicks to purchase a user upgrade.
     *
     * @param Controller      $controller
     * @param PurchaseRequest $purchaseRequest
     * @param Purchase        $purchase
     * @return \XF\Mvc\Reply\AbstractReply
     */
    public function initiatePayment(
        Controller $controller,
        PurchaseRequest $purchaseRequest,
        Purchase $purchase
    ) {
        $paymentProfile = $purchaseRequest->PaymentProfile;
        $options = $paymentProfile->options;

        $apiUrl  = rtrim($options['api_url'] ?? 'https://api.payzcore.com', '/');
        $apiKey  = $options['api_key'] ?? '';
        $expiry  = max(10, min(1440, intval($options['expiry_minutes'] ?? 60))) * 60;

        $enabledNetworks = $this->getEnabledNetworks($options);
        $defaultToken    = $this->getDefaultToken($options);

        // Check if user has selected a network (POST from network selector form)
        $request = $controller->getRequest();
        $selectedNetwork = $request->filter('payzcore_network', 'str');
        $selectedToken   = $request->filter('payzcore_token', 'str');

        // Determine if we need to show the network selector
        $needsSelector = false;

        if (empty($selectedNetwork)) {
            // No network selected yet
            if (count($enabledNetworks) > 1) {
                // Multiple networks enabled: show selector
                $needsSelector = true;
            } else {
                // Single network: use it directly
                $selectedNetwork = $enabledNetworks[0];
                $selectedToken = $defaultToken;
            }
        }

        // Validate selected network is in enabled list
        if (!$needsSelector && !in_array($selectedNetwork, $enabledNetworks)) {
            $selectedNetwork = $enabledNetworks[0];
        }

        // Validate selected token
        if (!$needsSelector) {
            if (empty($selectedToken) || !in_array($selectedToken, $this->validTokens)) {
                $selectedToken = $defaultToken;
            }
            // TRC20 only supports USDT
            if ($selectedNetwork === 'TRC20' && $selectedToken === 'USDC') {
                $selectedToken = 'USDT';
            }
        }

        // Step 1: Show network selector
        if ($needsSelector) {
            // Build the form action URL that will submit back to this same flow
            $createPaymentUrl = \XF::app()->router('public')->buildLink(
                'purchase', null,
                [
                    'payment_profile_id' => $paymentProfile->payment_profile_id,
                    'purchase_request'   => $purchaseRequest->request_key,
                ]
            );

            // Check if USDC is available on any enabled network (not just TRC20)
            $hasNonTrc20Network = false;
            foreach ($enabledNetworks as $network) {
                if ($network !== 'TRC20') {
                    $hasNonTrc20Network = true;
                    break;
                }
            }
            // Show token selector if there are non-TRC20 networks (USDC available)
            $showTokenSelector = $hasNonTrc20Network;

            $viewParams = [
                'purchaseRequest'    => $purchaseRequest,
                'showNetworkSelector' => true,
                'enabledNetworks'    => $this->buildNetworkOptions($enabledNetworks),
                'defaultNetwork'     => $enabledNetworks[0],
                'defaultToken'       => $defaultToken,
                'showTokenSelector'  => $showTokenSelector,
                'costAmount'         => number_format(floatval($purchaseRequest->cost_amount), 2),
                'createPaymentUrl'   => $createPaymentUrl,
            ];

            return $controller->view(
                'PayzCore:Payment\NetworkSelect',
                'payzcore_payment',
                $viewParams
            );
        }

        // Step 2: Create monitoring request with the selected network/token
        $network = $selectedNetwork;
        $token   = $selectedToken;

        // Build metadata for webhook reconciliation
        $metadata = [
            'request_key'  => $purchaseRequest->request_key,
            'purchase_id'  => $purchaseRequest->purchase_request_id,
            'user_id'      => $purchaseRequest->user_id,
            'purchasable'  => $purchaseRequest->purchasable_type_id,
            'source'       => 'xenforo',
        ];

        // Create monitoring request via PayzCore API
        $response = $this->apiRequest($apiUrl, $apiKey, 'POST', '/v1/payments', [
            'amount'            => floatval($purchaseRequest->cost_amount),
            'network'           => $network,
            'token'             => $token,
            'external_ref'      => 'xf-user-' . $purchaseRequest->user_id,
            'external_order_id' => 'XF-' . $purchaseRequest->purchase_request_id,
            'expires_in'        => $expiry,
            'metadata'          => $metadata,
        ]);

        if (!$response || !isset($response['success']) || $response['success'] !== true) {
            $errorMsg = isset($response['error']) ? $response['error'] : 'Unknown API error';
            \XF::logError('PayzCore: Failed to create monitoring request: ' . $errorMsg);
            throw $controller->exception(
                $controller->error(\XF::phrase('payzcore_monitoring_request_failed'))
            );
        }

        $payment = $response['payment'];

        // Store the PayzCore payment ID in the purchase request for later reference
        $purchaseRequest->fastUpdate('provider_metadata', $payment['id']);

        // Prepare template variables
        $networkLabel = isset($this->networkLabels[$network]) ? $this->networkLabels[$network] : $network;

        $viewParams = [
            'purchaseRequest'    => $purchaseRequest,
            'showNetworkSelector' => false,
            'payment'            => $payment,
            'networkLabel'       => $networkLabel,
            'token'              => $token,
            'callbackUrl'       => $this->getCallbackUrl(),
            'pollUrl'           => $this->getPollUrl($payment['id'], $purchaseRequest->request_key),
            'apiUrl'            => $apiUrl,
            'showTxidForm'      => !empty($payment['requires_txid']),
            'confirmEndpoint'   => $payment['confirm_endpoint'] ?? '',
        ];

        return $controller->view(
            'PayzCore:Payment\Initiate',
            'payzcore_payment',
            $viewParams
        );
    }

    /**
     * Process an existing payment (e.g., user returns to the payment page).
     *
     * @param Controller      $controller
     * @param PurchaseRequest $purchaseRequest
     * @param PaymentProfile  $paymentProfile
     * @param Purchase        $purchase
     * @return \XF\Mvc\Reply\AbstractReply
     */
    public function processPayment(
        Controller $controller,
        PurchaseRequest $purchaseRequest,
        PaymentProfile $paymentProfile,
        Purchase $purchase
    ) {
        // Verify the current visitor owns this purchase request
        $visitor = \XF::visitor();
        if ($visitor->user_id && $visitor->user_id !== $purchaseRequest->user_id) {
            throw $controller->exception($controller->noPermission());
        }

        $options  = $paymentProfile->options;
        $apiUrl   = rtrim($options['api_url'] ?? 'https://api.payzcore.com', '/');
        $apiKey   = $options['api_key'] ?? '';

        $paymentId = $purchaseRequest->provider_metadata;

        if (!empty($paymentId)) {
            // Fetch existing payment status
            $response = $this->apiRequest($apiUrl, $apiKey, 'GET', '/v1/payments/' . urlencode($paymentId));

            if ($response && isset($response['success']) && $response['success'] === true) {
                $payment = $response['payment'];

                // If already completed, redirect to the return URL
                if (in_array($payment['status'], ['paid', 'overpaid'])) {
                    return $controller->redirect($purchase->returnUrl);
                }

                // If not expired, show the existing payment
                if (!in_array($payment['status'], ['expired', 'cancelled'])) {
                    // Determine network/token from the payment response
                    $network = $payment['network'] ?? ($options['network'] ?? 'TRC20');
                    $token = $payment['token'] ?? $this->getDefaultToken($options);
                    $networkLabel = isset($this->networkLabels[$network]) ? $this->networkLabels[$network] : $network;

                    return $controller->view(
                        'PayzCore:Payment\Initiate',
                        'payzcore_payment',
                        [
                            'purchaseRequest'    => $purchaseRequest,
                            'showNetworkSelector' => false,
                            'payment'            => $payment,
                            'networkLabel'       => $networkLabel,
                            'token'              => $token,
                            'callbackUrl'       => $this->getCallbackUrl(),
                            'pollUrl'           => $this->getPollUrl($paymentId, $purchaseRequest->request_key),
                            'apiUrl'            => $apiUrl,
                            'showTxidForm'      => !empty($payment['requires_txid']),
                            'confirmEndpoint'   => $payment['confirm_endpoint'] ?? '',
                        ]
                    );
                }
            }
        }

        // If no existing valid payment, create a new one via initiatePayment
        return $this->initiatePayment($controller, $purchaseRequest, $purchase);
    }

    // -------------------------------------------------------------------------
    // Callback / Webhook Handling
    // -------------------------------------------------------------------------

    /**
     * Set up the callback state from the incoming webhook request.
     *
     * Reads the raw body and extracts relevant fields from the PayzCore
     * webhook payload. This is called by XenForo's payment_callback.php.
     *
     * @param \XF\Http\Request $request
     * @return CallbackState
     */
    public function setupCallback(\XF\Http\Request $request)
    {
        $state = new CallbackState();

        // Check if this is a poll request (client-side status check)
        $action = $request->filter('_xfAction', 'str');
        if ($action === 'poll') {
            return $this->handlePollRequest($request, $state);
        }

        // Read raw body and signature
        $state->inputRaw  = $request->getInputRaw();
        $state->signature = $request->getServer('HTTP_X_PAYZCORE_SIGNATURE');

        // Parse the JSON payload
        $payload = @json_decode($state->inputRaw, true);

        if (!is_array($payload)) {
            $state->logType    = 'error';
            $state->logMessage = 'Invalid JSON payload received.';
            return $state;
        }

        $state->payload = $payload;

        // Extract the event type
        $state->eventType = isset($payload['event']) ? $payload['event'] : '';

        // Extract transaction ID (tx_hash or fallback to payment_id)
        $txHash    = isset($payload['tx_hash']) ? $payload['tx_hash'] : '';
        $paymentId = isset($payload['payment_id']) ? $payload['payment_id'] : '';
        $state->transactionId = !empty($txHash) ? $txHash : ('payzcore-' . $paymentId);

        // Extract request key from metadata for purchase request lookup
        $metadata = isset($payload['metadata']) ? $payload['metadata'] : [];
        $state->requestKey = isset($metadata['request_key']) ? $metadata['request_key'] : '';

        // Fallback: try to find purchase request by external_order_id
        if (empty($state->requestKey) && !empty($payload['external_order_id'])) {
            $state->externalOrderId = $payload['external_order_id'];
        }

        // Store additional fields for logging
        $state->paymentId      = $paymentId;
        $state->paidAmount     = isset($payload['paid_amount']) ? $payload['paid_amount'] : '0';
        $state->expectedAmount = isset($payload['expected_amount']) ? $payload['expected_amount'] : '0';
        $state->network        = isset($payload['network']) ? $payload['network'] : '';
        $state->token          = isset($payload['token']) ? $payload['token'] : 'USDT';
        $state->address        = isset($payload['address']) ? $payload['address'] : '';
        $state->status         = isset($payload['status']) ? $payload['status'] : '';
        $state->txHash         = $txHash;

        return $state;
    }

    /**
     * Handle a poll request from the payment page JavaScript.
     *
     * This is a server-side proxy that keeps the API key on the server.
     * The client JS polls this endpoint to check payment status.
     *
     * @param \XF\Http\Request $request
     * @param CallbackState    $state
     * @return CallbackState
     */
    protected function handlePollRequest(\XF\Http\Request $request, CallbackState $state)
    {
        $paymentId  = $request->filter('payment_id', 'str');
        $requestKey = $request->filter('request_key', 'str');

        // Sanitize payment ID (UUID format)
        $paymentId = preg_replace('/[^a-zA-Z0-9\-]/', '', $paymentId);

        if (empty($paymentId) || empty($requestKey)) {
            $this->sendJsonResponse(['error' => 'Missing parameters'], 400);
            return $state;
        }

        // Validate that this request key corresponds to a real purchase request
        $purchaseRequest = \XF::em()->findOne('XF:PurchaseRequest', ['request_key' => $requestKey]);

        if (!$purchaseRequest) {
            $this->sendJsonResponse(['error' => 'Invalid request'], 403);
            return $state;
        }

        // Verify the payment ID matches what we stored
        if ($purchaseRequest->provider_metadata !== $paymentId) {
            $this->sendJsonResponse(['error' => 'Payment ID mismatch'], 403);
            return $state;
        }

        // Verify the current user owns this purchase request
        $visitor = \XF::visitor();
        if (!$visitor->user_id || $visitor->user_id !== $purchaseRequest->user_id) {
            $this->sendJsonResponse(['error' => 'Access denied'], 403);
            return $state;
        }

        // Get payment profile options for API credentials
        $paymentProfile = $purchaseRequest->PaymentProfile;
        if (!$paymentProfile) {
            $this->sendJsonResponse(['error' => 'Configuration error'], 500);
            return $state;
        }

        $options = $paymentProfile->options;
        $apiUrl  = rtrim($options['api_url'] ?? 'https://api.payzcore.com', '/');
        $apiKey  = $options['api_key'] ?? '';

        // Fetch payment status from PayzCore API
        $response = $this->apiRequest($apiUrl, $apiKey, 'GET', '/v1/payments/' . urlencode($paymentId));

        if (!$response || !isset($response['success']) || $response['success'] !== true) {
            $this->sendJsonResponse(['error' => 'Upstream error'], 502);
            return $state;
        }

        $payment = $response['payment'];

        // Return only safe fields (no sensitive data leakage)
        $this->sendJsonResponse([
            'success' => true,
            'payment' => [
                'status'      => $payment['status'] ?? 'pending',
                'paid_amount' => $payment['paid_amount'] ?? '0',
            ],
        ], 200);

        $state->logType    = 'info';
        $state->logMessage = 'Poll request handled.';
        return $state;
    }

    /**
     * Send a JSON response.
     *
     * Used for poll requests that bypass the normal callback flow.
     * Caller must return $state after calling this method.
     *
     * @param array $data
     * @param int   $statusCode
     */
    protected function sendJsonResponse(array $data, $statusCode = 200)
    {
        http_response_code($statusCode);
        header('Content-Type: application/json');
        header('Cache-Control: no-cache, no-store, must-revalidate');
        echo json_encode($data);
        exit;
    }

    /**
     * Validate the incoming webhook callback.
     *
     * Verifies the HMAC-SHA256 signature to ensure the webhook is authentic.
     *
     * @param CallbackState $state
     * @return bool
     */
    public function validateCallback(CallbackState $state)
    {
        $paymentProfile = $state->getPaymentProfile();

        if (!$paymentProfile) {
            $state->logType    = 'error';
            $state->logMessage = 'No payment profile found for this callback.';
            return false;
        }

        $webhookSecret = $paymentProfile->options['webhook_secret'] ?? '';

        if (empty($webhookSecret)) {
            $state->logType    = 'error';
            $state->logMessage = 'Webhook secret not configured in payment profile.';
            return false;
        }

        if (empty($state->signature)) {
            $state->logType    = 'error';
            $state->logMessage = 'Missing X-PayzCore-Signature header.';
            return false;
        }

        if (empty($state->inputRaw)) {
            $state->logType    = 'error';
            $state->logMessage = 'Empty request body.';
            return false;
        }

        // Timestamp is required for signature verification
        $timestamp = $_SERVER['HTTP_X_PAYZCORE_TIMESTAMP'] ?? '';
        if (empty($timestamp)) {
            $state->logType    = 'error';
            $state->logMessage = 'Missing X-PayzCore-Timestamp header.';
            return false;
        }

        // Replay protection (±5 minutes)
        $ts = strtotime($timestamp);
        if ($ts === false || abs(time() - $ts) > 300) {
            $state->logType    = 'error';
            $state->logMessage = 'Timestamp validation failed or expired.';
            return false;
        }

        // Verify HMAC-SHA256 signature (covers timestamp + body, timing-safe comparison)
        $message = $timestamp . '.' . $state->inputRaw;
        $expected = hash_hmac('sha256', $message, $webhookSecret);
        if (!hash_equals($expected, $state->signature)) {
            $state->logType    = 'error';
            $state->logMessage = 'Invalid HMAC-SHA256 signature.';
            return false;
        }

        return true;
    }

    /**
     * Validate the transaction for duplicate processing.
     *
     * @param CallbackState $state
     * @return bool
     */
    public function validateTransaction(CallbackState $state)
    {
        // Must have a request key to identify the purchase
        if (empty($state->requestKey)) {
            // Try fallback via external_order_id
            if (!empty($state->externalOrderId)) {
                $purchaseRequest = $this->findPurchaseRequestByOrderId($state->externalOrderId);
                if ($purchaseRequest) {
                    $state->requestKey = $purchaseRequest->request_key;
                }
            }

            if (empty($state->requestKey)) {
                $state->logType    = 'info';
                $state->logMessage = 'No purchase request key found. Unrelated webhook, no action.';
                return false;
            }
        }

        if (!$state->getPurchaseRequest()) {
            $state->logType    = 'info';
            $state->logMessage = 'Invalid request key. Purchase request not found.';
            return false;
        }

        if (empty($state->transactionId)) {
            $state->logType    = 'info';
            $state->logMessage = 'No transaction ID. No action to take.';
            return false;
        }

        // Check for duplicate transaction (idempotency)
        /** @var \XF\Repository\Payment $paymentRepo */
        $paymentRepo = \XF::repository('XF:Payment');
        $matchingLogs = $paymentRepo->findLogsByTransactionIdForProvider(
            $state->transactionId,
            $this->providerId
        )->where('log_type', '=', 'payment');

        if ($matchingLogs->total()) {
            $state->logType    = 'info';
            $state->logMessage = 'Transaction already processed. Skipping duplicate.';
            return false;
        }

        return true;
    }

    /**
     * Determine the payment result from the webhook event.
     *
     * Maps PayzCore events to XenForo payment states.
     *
     * @param CallbackState $state
     * @return int|null  CallbackState::PAYMENT_RECEIVED or null
     */
    public function getPaymentResult(CallbackState $state)
    {
        $event = $state->eventType ?? '';
        $token   = $state->token ?? 'USDT';
        $network = $state->network ?? '';

        switch ($event) {
            case 'payment.completed':
                $state->logType    = 'payment';
                $state->logMessage = 'Transfer confirmed: '
                    . $state->paidAmount . ' ' . $token
                    . ' on ' . $network . '.';
                $state->paymentResult = CallbackState::PAYMENT_RECEIVED;
                return CallbackState::PAYMENT_RECEIVED;

            case 'payment.overpaid':
                $state->logType    = 'payment';
                $state->logMessage = 'Transfer confirmed (overpaid): '
                    . $state->paidAmount . ' ' . $token
                    . ' received, expected ' . $state->expectedAmount . ' ' . $token
                    . ' on ' . $network . '.';
                $state->paymentResult = CallbackState::PAYMENT_RECEIVED;
                return CallbackState::PAYMENT_RECEIVED;

            case 'payment.partial':
                $state->logType    = 'info';
                $state->logMessage = 'Partial transfer detected: '
                    . $state->paidAmount . ' ' . $token
                    . ' of ' . $state->expectedAmount . ' ' . $token
                    . ' on ' . $network . '. Waiting for remaining amount.';
                return null;

            case 'payment.expired':
                $state->logType    = 'info';
                $state->logMessage = 'Monitoring window expired for '
                    . $state->expectedAmount . ' ' . $token
                    . ' on ' . $network . '. No action taken.';
                return null;

            case 'payment.cancelled':
                $state->logType    = 'info';
                $state->logMessage = 'Payment cancelled by the merchant for '
                    . $state->expectedAmount . ' ' . $token
                    . ' on ' . $network . '.';
                return null;

            default:
                $state->logType    = 'info';
                $state->logMessage = 'Unknown event type: ' . $event . '. Logged for reference.';
                return null;
        }
    }

    /**
     * Prepare data for the payment log entry.
     *
     * @param CallbackState $state
     * @return void
     */
    public function prepareLogData(CallbackState $state)
    {
        $state->logDetails = [
            'event'           => $state->eventType ?? '',
            'payment_id'      => $state->paymentId ?? '',
            'network'         => $state->network ?? '',
            'token'           => $state->token ?? '',
            'expected_amount' => $state->expectedAmount ?? '',
            'paid_amount'     => $state->paidAmount ?? '',
            'tx_hash'         => $state->txHash ?? '',
            'address'         => $state->address ?? '',
            'status'          => $state->status ?? '',
            'signature'       => !empty($state->signature) ? substr($state->signature, 0, 16) . '...' : '',
            'body'            => $state->inputRaw ?? '',
        ];
    }

    /**
     * Recurring payments are not supported.
     *
     * PayzCore monitors one-time stablecoin transfers. For recurring
     * user upgrades, the user must pay each renewal individually.
     *
     * @param PaymentProfile $paymentProfile
     * @param string         $unit
     * @param int            $amount
     * @param int            $result
     * @return bool
     */
    public function supportsRecurring(
        PaymentProfile $paymentProfile,
        $unit,
        $amount,
        &$result = self::ERR_NO_RECURRING
    ) {
        $result = self::ERR_NO_RECURRING;
        return false;
    }

    /**
     * Verify that a currency code is supported.
     *
     * PayzCore monitors stablecoin transfers denominated in USD.
     *
     * @param PaymentProfile $paymentProfile
     * @param string         $currencyCode
     * @return bool
     */
    public function verifyCurrency(PaymentProfile $paymentProfile, $currencyCode)
    {
        return strtoupper($currencyCode) === 'USD';
    }

    // -------------------------------------------------------------------------
    // Cancellation (not supported)
    // -------------------------------------------------------------------------

    /**
     * Render cancellation template.
     *
     * Not applicable for PayzCore monitoring -- once a monitoring request
     * expires, it simply stops. No cancellation action is needed.
     *
     * @param PurchaseRequest $purchaseRequest
     * @return string
     */
    public function renderCancellationTemplate(PurchaseRequest $purchaseRequest)
    {
        return '';
    }

    // -------------------------------------------------------------------------
    // API Communication
    // -------------------------------------------------------------------------

    /**
     * Send an HTTP request to the PayzCore API.
     *
     * Uses XenForo's built-in HTTP client (Guzzle) for communication.
     *
     * @param string     $baseUrl API base URL
     * @param string     $apiKey  Project API key
     * @param string     $method  HTTP method (GET, POST)
     * @param string     $path    API endpoint path
     * @param array|null $body    Request body for POST requests
     * @return array|null Decoded JSON response or null on failure
     */
    protected function apiRequest($baseUrl, $apiKey, $method, $path, array $body = null)
    {
        $url = $baseUrl . $path;

        try {
            $client = \XF::app()->http()->client();

            $options = [
                'headers' => [
                    'x-api-key'  => $apiKey,
                    'Accept'     => 'application/json',
                    'User-Agent' => self::USER_AGENT,
                ],
                'timeout'         => self::TIMEOUT,
                'connect_timeout' => self::CONNECT_TIMEOUT,
                'allow_redirects' => false,
            ];

            if ($method === 'POST' && $body !== null) {
                $options['headers']['Content-Type'] = 'application/json';
                $options['body'] = json_encode($body);
            }

            $response = ($method === 'POST')
                ? $client->post($url, $options)
                : $client->get($url, $options);

            $httpCode     = $response->getStatusCode();
            $responseBody = $response->getBody()->getContents();
        } catch (\GuzzleHttp\Exception\ConnectException $e) {
            \XF::logError('PayzCore API connection error: ' . $e->getMessage());
            return null;
        } catch (\Exception $e) {
            \XF::logError('PayzCore API request error: ' . $e->getMessage());
            return null;
        }

        $decoded = @json_decode($responseBody, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            \XF::logError('PayzCore API invalid JSON response (HTTP ' . $httpCode . ')');
            return null;
        }

        if ($httpCode >= 400) {
            $errorMsg = isset($decoded['error']) ? $decoded['error'] : ('HTTP ' . $httpCode);
            \XF::logError('PayzCore API error: ' . $errorMsg . ' (HTTP ' . $httpCode . ')');
            return $decoded;
        }

        return $decoded;
    }

    /**
     * Test API connectivity by making a GET request.
     *
     * @param string $apiUrl
     * @param string $apiKey
     * @return true|string True on success, error string on failure
     */
    protected function testApiConnection($apiUrl, $apiKey)
    {
        $response = $this->apiRequest($apiUrl, $apiKey, 'GET', '/v1/config');

        if ($response === null) {
            return 'Could not connect to PayzCore API at ' . $apiUrl;
        }

        if (isset($response['error'])) {
            return 'API error: ' . $response['error'] . '. Check your project credentials.';
        }

        return true;
    }

    /**
     * Find a purchase request by external order ID.
     *
     * @param string $externalOrderId
     * @return PurchaseRequest|null
     */
    protected function findPurchaseRequestByOrderId($externalOrderId)
    {
        // External order ID format: XF-{purchase_request_id}
        if (preg_match('/^XF-(\d+)$/', $externalOrderId, $matches)) {
            $purchaseRequestId = intval($matches[1]);
            return \XF::em()->find('XF:PurchaseRequest', $purchaseRequestId);
        }

        return null;
    }

    /**
     * Build the URL for client-side status polling.
     *
     * @param string $paymentId   PayzCore payment UUID
     * @param string $requestKey  Purchase request key for validation
     * @return string
     */
    protected function getPollUrl($paymentId, $requestKey)
    {
        return \XF::app()->options()->boardUrl
            . '/payment_callback.php?_xfProvider=' . urlencode($this->providerId)
            . '&_xfAction=poll'
            . '&payment_id=' . urlencode($paymentId)
            . '&request_key=' . urlencode($requestKey);
    }

    /**
     * Get the webhook callback URL for PayzCore.
     *
     * @return string
     */
    public function getCallbackUrl()
    {
        return \XF::app()->options()->boardUrl
            . '/payment_callback.php?_xfProvider=' . urlencode($this->providerId);
    }
}
